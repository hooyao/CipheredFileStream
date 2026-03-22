using System.Runtime.CompilerServices;
using CipheredFileStream.IO.Exceptions;

namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Manages block-level encryption/decryption with single-block caching.
/// Used by the RandomAccess path and as fallback from Sequential mode.
///
/// Block format on disk:
/// Block 0: [CleartextHeader 32B][CiphertextLength 4B][Ciphertext...][Padding...]
/// Block N: [CiphertextLength 4B][Ciphertext...][Padding...]
/// </summary>
internal sealed class BlockManager : IDisposable
{
    private readonly Stream _underlyingStream;
    private readonly byte[] _key;
    private readonly IntegrityTracker _integrityTracker;
    private readonly BlockLayout _layout;
    private readonly PositionMapper _positionMapper;
    private readonly string? _filePath;

    // Block cache
    private readonly byte[] _cachedPayload;
    private int _cachedBlockIndex = -1;
    private bool _isDirty;

    // Working buffers
    private readonly byte[] _ciphertextBuffer;
    private readonly byte[] _plaintextBuffer;
    private readonly byte[] _aadBuffer;
    private readonly byte[] _integrityTagBuffer;
    private readonly byte[] _paddingBuffer;

    // Pluggable crypto
    private readonly IBlockCrypto _crypto;

    public BlockManager(
        Stream underlyingStream,
        byte[] key,
        IntegrityTracker integrityTracker,
        BlockLayout layout,
        PositionMapper positionMapper,
        IBlockCryptoFactory cryptoFactory,
        string? filePath = null)
    {
        _underlyingStream = underlyingStream;
        _key = key;
        _integrityTracker = integrityTracker;
        _layout = layout;
        _positionMapper = positionMapper;
        _filePath = filePath;

        _cachedPayload = new byte[layout.PayloadCapacity];
        _ciphertextBuffer = new byte[layout.BlockSize];
        _plaintextBuffer = new byte[layout.BlockSize];
        _aadBuffer = new byte[EncryptedFileFormat.AadSize];
        _integrityTagBuffer = new byte[EncryptedFileFormat.IntegrityHashSize];
        _paddingBuffer = new byte[layout.BlockSize]; // pre-allocated zeros
        _crypto = cryptoFactory.Create(layout.BlockNMaxCiphertextSize);
    }

    public int CachedBlockIndex => _cachedBlockIndex;
    public bool IsDirty => _isDirty;

    public void EnsureBlock(int blockIndex, bool isNewBlock = false)
    {
        if (_cachedBlockIndex == blockIndex)
            return;

        if (_isDirty && _cachedBlockIndex >= 0)
            FlushBlock();

        if (isNewBlock)
        {
            Array.Clear(_cachedPayload, 0, _cachedPayload.Length);
            _cachedBlockIndex = blockIndex;
            _isDirty = false;
        }
        else
        {
            LoadBlock(blockIndex);
        }
    }

    private void LoadBlock(int blockIndex)
    {
        long physicalOffset = _positionMapper.GetPhysicalOffset(blockIndex);
        _underlyingStream.Position = physicalOffset;

        if (blockIndex == 0)
            _underlyingStream.Position = physicalOffset + EncryptedFileFormat.CleartextHeaderSize;

        // Read ciphertext length prefix
        Span<byte> lengthBytes = stackalloc byte[_layout.CiphertextLengthPrefixSize];
        int lengthRead = _underlyingStream.Read(lengthBytes);
        if (lengthRead < _layout.CiphertextLengthPrefixSize)
            throw new EndOfStreamException($"Failed to read ciphertext length for block {blockIndex}.");

        int ciphertextLength = (int)BitConverter.ToUInt32(lengthBytes);
        int maxCiphertextSize = blockIndex == 0 ? _layout.Block0MaxCiphertextSize : _layout.BlockNMaxCiphertextSize;
        if (ciphertextLength == 0 || ciphertextLength > maxCiphertextSize)
            throw new EncryptedFileCorruptException($"Invalid ciphertext length {ciphertextLength} for block {blockIndex}.", blockIndex, _filePath);

        // Read ciphertext
        int bytesRead = _underlyingStream.Read(_ciphertextBuffer, 0, ciphertextLength);
        if (bytesRead < ciphertextLength)
            throw new EndOfStreamException($"Failed to read block {blockIndex}: expected {ciphertextLength} bytes, got {bytesRead}.");

        // Decrypt — produces integrity tag as a side effect
        BitConverter.TryWriteBytes(_aadBuffer, (long)blockIndex);
        int decryptedLength = _crypto.Decrypt(
            _key, _ciphertextBuffer, 0, ciphertextLength,
            _aadBuffer, _plaintextBuffer, 0, _integrityTagBuffer);

        if (decryptedLength == -1)
            throw EncryptedFileCorruptException.BlockAuthenticationFailed(blockIndex, _filePath);

        Array.Copy(_plaintextBuffer, 0, _cachedPayload, 0, decryptedLength);

        // Record integrity tag (obtained from IBlockCrypto, not extracted from ciphertext)
        _integrityTracker.RecordBlockHash(blockIndex, _integrityTagBuffer);

        _cachedBlockIndex = blockIndex;
        _isDirty = false;
    }

    public void FlushBlock()
    {
        if (!_isDirty || _cachedBlockIndex < 0)
            return;

        // Encrypt
        BitConverter.TryWriteBytes(_aadBuffer, (long)_cachedBlockIndex);
        int ciphertextLength = _crypto.Encrypt(
            _key, _cachedPayload, 0, _layout.PayloadCapacity,
            _aadBuffer, _ciphertextBuffer, 0, _integrityTagBuffer);

        if (ciphertextLength < 0)
            throw new InvalidOperationException($"Encryption failed for block {_cachedBlockIndex}.");

        // Update integrity with the tag from IBlockCrypto
        _integrityTracker.UpdateIntegrity(_cachedBlockIndex, _integrityTagBuffer);

        // Write to disk
        long physicalOffset = _positionMapper.GetPhysicalOffset(_cachedBlockIndex);

        if (_cachedBlockIndex == 0)
            _underlyingStream.Position = physicalOffset + EncryptedFileFormat.CleartextHeaderSize;
        else
            _underlyingStream.Position = physicalOffset;

        // Length prefix
        Span<byte> lengthBytes = stackalloc byte[4];
        BitConverter.TryWriteBytes(lengthBytes, (uint)ciphertextLength);
        _underlyingStream.Write(lengthBytes);

        // Ciphertext
        _underlyingStream.Write(_ciphertextBuffer, 0, ciphertextLength);

        // Padding
        int totalWritten = _layout.CiphertextLengthPrefixSize + ciphertextLength;
        int paddingNeeded = (_cachedBlockIndex == 0
            ? _layout.BlockSize - EncryptedFileFormat.CleartextHeaderSize
            : _layout.BlockSize) - totalWritten;

        if (paddingNeeded > 0)
            _underlyingStream.Write(_paddingBuffer, 0, paddingNeeded);

        _isDirty = false;
    }

    public int ReadFromCache(int offsetInPayload, byte[] buffer, int offset, int count)
    {
        int available = _layout.PayloadCapacity - offsetInPayload;
        int toRead = Math.Min(count, Math.Max(0, available));
        if (toRead > 0)
            Array.Copy(_cachedPayload, offsetInPayload, buffer, offset, toRead);
        return toRead;
    }

    public void WriteToCache(int offsetInPayload, byte[] buffer, int offset, int count)
    {
        Array.Copy(buffer, offset, _cachedPayload, offsetInPayload, count);
        _isDirty = true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Span<byte> GetCachedPayloadSpan()
        => _cachedPayload.AsSpan(0, _layout.PayloadCapacity);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void MarkDirty() => _isDirty = true;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void InvalidateCache()
    {
        _cachedBlockIndex = -1;
        _isDirty = false;
    }

    public void Dispose()
    {
        _crypto.Dispose();
        Array.Clear(_cachedPayload);
        Array.Clear(_plaintextBuffer);
        Array.Clear(_ciphertextBuffer);
        Array.Clear(_integrityTagBuffer);
    }
}
