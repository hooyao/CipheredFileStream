using System.Buffers.Binary;
using System.Security.Cryptography;
using CipheredFileStream.Proto;
using Google.Protobuf;

namespace CipheredFileStream;

/// <summary>
/// A Stream implementation that provides transparent AES-GCM encryption for files.
/// Files are encrypted and stored in chunks for efficient random access.
/// </summary>
public sealed class CipheredFileStream : Stream
{
    private readonly FileStream _fileStream;
    private readonly byte[] _key;
    private readonly ChunkSize _chunkSize;
    private readonly int _chunkSizeBytes;
    private readonly FileMode _mode;
    private readonly FileAccess _access;

    private FileHeader? _header;
    private long _position;
    private bool _disposed;
    private ulong _plaintextLength;
    private uint _chunkCount;

    // Cache for current chunk (plaintext data only, not including header metadata)
    private byte[]? _cachedChunkData;
    private int _cachedChunkIndex = -1;
    private bool _cachedChunkDirty;

    /// <summary>
    /// Creates a new CipheredFileStream with a raw encryption key.
    /// </summary>
    public CipheredFileStream(
        string path,
        FileMode mode,
        FileAccess access,
        ReadOnlySpan<byte> key,
        ChunkSize chunkSize = ChunkSize.Size4K)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (key.Length != FileFormat.KeySize)
            throw new ArgumentException($"Key must be {FileFormat.KeySize} bytes.", nameof(key));

        _key = key.ToArray();
        _chunkSize = chunkSize;
        _chunkSizeBytes = (int)chunkSize;
        _mode = mode;
        _access = access;

        var fileAccess = access == FileAccess.Read ? FileAccess.Read : FileAccess.ReadWrite;
        _fileStream = new FileStream(path, mode, fileAccess, FileShare.Read, 4096, FileOptions.None);

        Initialize(mode);
    }

    /// <summary>
    /// Creates a new CipheredFileStream with a password.
    /// </summary>
    public CipheredFileStream(
        string path,
        FileMode mode,
        FileAccess access,
        ReadOnlySpan<char> password,
        ChunkSize chunkSize = ChunkSize.Size4K)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (password.Length == 0)
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        _chunkSize = chunkSize;
        _chunkSizeBytes = (int)chunkSize;
        _mode = mode;
        _access = access;

        var fileAccess = access == FileAccess.Read ? FileAccess.Read : FileAccess.ReadWrite;
        _fileStream = new FileStream(path, mode, fileAccess, FileShare.Read, 4096, FileOptions.None);

        if (mode == FileMode.Create || mode == FileMode.CreateNew)
        {
            var salt = RandomNumberGenerator.GetBytes(FileFormat.SaltSize);
            _key = FileFormat.DeriveKeyFromPassword(password, salt, FileFormat.DefaultPbkdf2Iterations);
            Initialize(mode, salt);
        }
        else
        {
            // Read salt from cleartext header
            _fileStream.Seek(FileFormat.MagicNumber.Length, SeekOrigin.Begin);
            var salt = new byte[FileFormat.SaltSize];
            _fileStream.ReadExactly(salt);
            _key = FileFormat.DeriveKeyFromPassword(password, salt, FileFormat.DefaultPbkdf2Iterations);
            
            // Now read the full header with derived key
            ReadHeader();
            if (_header?.KeyInfo?.Method != KeyDerivation.Pbkdf2)
                throw new InvalidOperationException("File was not created with password-based encryption.");
        }
    }

    private void Initialize(FileMode mode, byte[]? salt = null)
    {
        if (mode == FileMode.Create || mode == FileMode.CreateNew)
        {
            CreateNewFile(salt);
        }
        else if (mode == FileMode.Open || mode == FileMode.OpenOrCreate)
        {
            if (_fileStream.Length > 0)
            {
                ReadHeader();
            }
            else if (mode == FileMode.OpenOrCreate)
            {
                CreateNewFile(salt);
            }
            else
            {
                throw new FileNotFoundException("File not found or is empty.");
            }
        }
        else if (mode == FileMode.Append)
        {
            if (_fileStream.Length > 0)
            {
                ReadHeader();
                _position = (long)_plaintextLength;
            }
            else
            {
                CreateNewFile(salt);
            }
        }
    }

    private void CreateNewFile(byte[]? salt)
    {
        var masterNonce = RandomNumberGenerator.GetBytes(FileFormat.MasterNonceSize);

        _header = new FileHeader
        {
            ChunkSize = ConvertChunkSize(_chunkSize),
            MasterNonce = ByteString.CopyFrom(masterNonce),
            TotalChecksum = ByteString.CopyFrom(new byte[FileFormat.ChecksumSize]),
            KeyInfo = salt is not null
                ? new KeyInfo { Method = KeyDerivation.Pbkdf2, Salt = ByteString.CopyFrom(salt), Iterations = (uint)FileFormat.DefaultPbkdf2Iterations }
                : new KeyInfo { Method = KeyDerivation.None }
        };

        _plaintextLength = 0;
        _chunkCount = 0;

        // Write chunk 0 with header
        WriteChunk0();
        _position = 0;
    }

    private void ReadHeader()
    {
        _fileStream.Seek(0, SeekOrigin.Begin);

        // Read cleartext magic (8 bytes)
        var magic = new byte[FileFormat.MagicNumber.Length];
        if (_fileStream.Read(magic, 0, magic.Length) != magic.Length ||
            !magic.AsSpan().SequenceEqual(FileFormat.MagicNumber))
        {
            throw new InvalidDataException("Not a valid CipheredFileStream file.");
        }

        // Read salt (16 bytes cleartext)
        var salt = new byte[FileFormat.SaltSize];
        _fileStream.ReadExactly(salt);

        // Read ciphertext length (4 bytes)
        Span<byte> ctLengthBuf = stackalloc byte[4];
        _fileStream.ReadExactly(ctLengthBuf);
        var ctLength = BinaryPrimitives.ReadUInt32LittleEndian(ctLengthBuf);

        // Read encrypted envelope: nonce + ciphertext + tag
        var envelope = new byte[ctLength + FileFormat.NonceSize + FileFormat.TagSize];
        if (_fileStream.Read(envelope, 0, envelope.Length) != envelope.Length)
            throw new InvalidDataException("Failed to read chunk 0 envelope.");

        // Decrypt chunk 0
        var nonce = envelope.AsSpan(0, FileFormat.NonceSize);
        var ciphertext = envelope.AsSpan(FileFormat.NonceSize, (int)ctLength);
        var tag = envelope.AsSpan(FileFormat.NonceSize + (int)ctLength, FileFormat.TagSize);

        Span<byte> aad = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(aad, 0);  // Chunk 0 AAD = 0

        var plaintext = new byte[ctLength];
        using var aesGcm = new AesGcm(_key, FileFormat.TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        // Parse header from decrypted payload
        var headerLength = BinaryPrimitives.ReadUInt16LittleEndian(plaintext.AsSpan(0, 2));
        var headerBytes = new byte[headerLength];
        Array.Copy(plaintext, 2, headerBytes, 0, headerLength);
        _header = FileHeader.Parser.ParseFrom(headerBytes);

        // Read metadata at fixed offset (2 + 128)
        _plaintextLength = BinaryPrimitives.ReadUInt64LittleEndian(plaintext.AsSpan(2 + 128, 8));
        _chunkCount = BinaryPrimitives.ReadUInt32LittleEndian(plaintext.AsSpan(2 + 128 + 8, 4));

        // Verify chunk size matches
        var expectedChunkSize = ConvertChunkSize(_chunkSize);
        if (_header.ChunkSize != expectedChunkSize)
            throw new InvalidDataException($"File chunk size {_header.ChunkSize} does not match requested size {expectedChunkSize}.");
    }

    private void WriteChunk0()
    {
        if (_header is null)
            throw new InvalidOperationException("Header not initialized.");

        // Serialize protobuf header
        var headerBytes = _header.ToByteArray();

        // Fixed metadata size: 2 (hdr len) + 128 (protobuf max) + 8 (plaintext_length) + 4 (chunk_count) = 142
        const int fixedMetadataSize = 2 + 128 + 8 + 4;
        var chunk0DataCapacity = FileFormat.GetChunk0DataCapacity(_chunkSizeBytes);

        // Read existing chunk 0 user data if it exists
        byte[] existingUserData = Array.Empty<byte>();
        if (_fileStream.Length >= _chunkSizeBytes)
        {
            try
            {
                existingUserData = DecryptChunk(0);
            }
            catch
            {
                // Chunk 0 might not exist yet or be corrupted
            }
        }

        // Merge: use new data if chunk 0 is cached, otherwise use existing
        byte[] userData;
        if (_cachedChunkIndex == 0 && _cachedChunkData is not null)
        {
            // Use cached data (might be partial update)
            userData = new byte[chunk0DataCapacity];
            Array.Copy(existingUserData, userData, Math.Min(existingUserData.Length, userData.Length));
            Array.Copy(_cachedChunkData, 0, userData, 0, Math.Min(_cachedChunkData.Length, userData.Length));
        }
        else
        {
            // Use existing data
            userData = new byte[Math.Min(existingUserData.Length, chunk0DataCapacity)];
            Array.Copy(existingUserData, userData, userData.Length);
        }

        var plaintext = new byte[fixedMetadataSize + userData.Length];

        // Write header length
        BinaryPrimitives.WriteUInt16LittleEndian(plaintext.AsSpan(0, 2), (ushort)headerBytes.Length);

        // Write protobuf header (padded to 128 bytes)
        headerBytes.CopyTo(plaintext, 2);

        // Write metadata
        BinaryPrimitives.WriteUInt64LittleEndian(plaintext.AsSpan(2 + 128, 8), _plaintextLength);
        BinaryPrimitives.WriteUInt32LittleEndian(plaintext.AsSpan(2 + 128 + 8, 4), _chunkCount);

        // Copy user data
        if (userData.Length > 0)
        {
            Array.Copy(userData, 0, plaintext, fixedMetadataSize, userData.Length);
        }

        // Encrypt
        var nonce = FileFormat.DeriveChunkNonce(_header.MasterNonce.ToByteArray(), 0);
        Span<byte> aad = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(aad, 0);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[FileFormat.TagSize];
        using var aesGcm = new AesGcm(_key, FileFormat.TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        // Update total checksum with chunk 0
        var chunk0Checksum = FileFormat.ComputeChunkChecksum(nonce, ciphertext, tag);
        var totalChecksum = new byte[FileFormat.ChecksumSize];
        FileFormat.UpdateTotalChecksum(totalChecksum, new byte[FileFormat.ChecksumSize], chunk0Checksum);

        // Add checksums from other chunks
        for (int i = 1; i < (int)_chunkCount; i++)
        {
            try
            {
                var chunkPlaintext = DecryptChunk(i);
                var chunkNonce = FileFormat.DeriveChunkNonce(_header.MasterNonce.ToByteArray(), (uint)i);
                Span<byte> chunkAad = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32LittleEndian(chunkAad, (uint)i);
                var chunkCiphertext = new byte[chunkPlaintext.Length];
                var chunkTag = new byte[FileFormat.TagSize];
                using var chunkAes = new AesGcm(_key, FileFormat.TagSize);
                chunkAes.Encrypt(chunkNonce, chunkPlaintext, chunkCiphertext, chunkTag, chunkAad);
                var chunkChecksum = FileFormat.ComputeChunkChecksum(chunkNonce, chunkCiphertext, chunkTag);
                FileFormat.UpdateTotalChecksum(totalChecksum, new byte[FileFormat.ChecksumSize], chunkChecksum);
            }
            catch
            {
                // Chunk might not exist yet
            }
        }
        _header.TotalChecksum = ByteString.CopyFrom(totalChecksum);

        // Write to disk: magic + salt + ct_length + nonce + ciphertext + tag + padding
        _fileStream.Seek(0, SeekOrigin.Begin);
        _fileStream.Write(FileFormat.MagicNumber);

        // Write salt (16 bytes cleartext)
        var saltBytes = _header.KeyInfo?.Salt ?? ByteString.Empty;
        var salt = new byte[FileFormat.SaltSize];
        if (saltBytes.Length > 0)
            saltBytes.Span.CopyTo(salt);
        _fileStream.Write(salt);

        // Write ct_length
        var ctLengthBuf = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(ctLengthBuf, (uint)plaintext.Length);
        _fileStream.Write(ctLengthBuf);

        _fileStream.Write(nonce);
        _fileStream.Write(ciphertext);
        _fileStream.Write(tag);

        // Pad to chunk size
        var written = FileFormat.Chunk0CleartextSize + FileFormat.CtLengthSize + FileFormat.NonceSize + plaintext.Length + FileFormat.TagSize;
        if (written < _chunkSizeBytes)
            _fileStream.Write(new byte[_chunkSizeBytes - written]);

        _fileStream.Flush();
    }

    private byte[] DecryptChunk(int chunkIndex)
    {
        var chunkOffset = (long)chunkIndex * _chunkSizeBytes;
        _fileStream.Seek(chunkOffset, SeekOrigin.Begin);

        // For chunk 0, skip magic + salt (24 bytes) before ct_length
        if (chunkIndex == 0)
            _fileStream.Seek(FileFormat.MagicNumber.Length + FileFormat.SaltSize, SeekOrigin.Current);

        // Read ct_length
        Span<byte> ctLengthBuf = stackalloc byte[4];
        _fileStream.ReadExactly(ctLengthBuf);
        var ctLength = BinaryPrimitives.ReadUInt32LittleEndian(ctLengthBuf);

        if (ctLength == 0)
            return Array.Empty<byte>();

        // Read nonce + ciphertext + tag
        var nonce = new byte[FileFormat.NonceSize];
        _fileStream.ReadExactly(nonce);

        var ciphertext = new byte[ctLength];
        _fileStream.ReadExactly(ciphertext);

        var tag = new byte[FileFormat.TagSize];
        _fileStream.ReadExactly(tag);

        // Decrypt
        Span<byte> aad = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(aad, (uint)chunkIndex);

        var plaintext = new byte[ctLength];
        using var aesGcm = new AesGcm(_key, FileFormat.TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        // For chunk 0, skip fixed metadata to get user data
        if (chunkIndex == 0)
        {
            const int fixedMetadataSize = 2 + 128 + 8 + 4;  // Same as WriteChunk0
            var userData = new byte[plaintext.Length - fixedMetadataSize];
            if (userData.Length > 0)
                Array.Copy(plaintext, fixedMetadataSize, userData, 0, userData.Length);
            return userData;
        }

        return plaintext;
    }

    private void WriteChunk(int chunkIndex, ReadOnlySpan<byte> data)
    {
        if (_header is null)
            throw new InvalidOperationException("Header not initialized.");

        if (chunkIndex == 0)
        {
            // Chunk 0 is special - contains header + user data
            WriteChunk0();
            return;
        }

        // Chunk N: ct_length + nonce + ciphertext + tag + padding
        var nonce = FileFormat.DeriveChunkNonce(_header.MasterNonce.ToByteArray(), (uint)chunkIndex);
        Span<byte> aad = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(aad, (uint)chunkIndex);

        var ciphertext = new byte[data.Length];
        var tag = new byte[FileFormat.TagSize];
        using var aesGcm = new AesGcm(_key, FileFormat.TagSize);
        aesGcm.Encrypt(nonce, data, ciphertext, tag, aad);

        // Compute chunk checksum for integrity tracking
        var newChecksum = FileFormat.ComputeChunkChecksum(nonce, ciphertext, tag);

        // Write to disk
        var chunkOffset = (long)chunkIndex * _chunkSizeBytes;
        _fileStream.Seek(chunkOffset, SeekOrigin.Begin);

        // Write ct_length
        var ctLengthBuf = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(ctLengthBuf, (uint)data.Length);
        _fileStream.Write(ctLengthBuf);

        // Write nonce + ciphertext + tag
        _fileStream.Write(nonce);
        _fileStream.Write(ciphertext);
        _fileStream.Write(tag);

        // Pad to chunk size
        var written = FileFormat.CtLengthSize + FileFormat.NonceSize + data.Length + FileFormat.TagSize;
        if (written < _chunkSizeBytes)
            _fileStream.Write(new byte[_chunkSizeBytes - written]);

        _fileStream.Flush();
    }

    private void FlushCachedChunk()
    {
        if (_cachedChunkData is null || _cachedChunkIndex < 0 || !_cachedChunkDirty)
            return;

        WriteChunk(_cachedChunkIndex, _cachedChunkData.AsSpan(0, GetChunkDataSize(_cachedChunkIndex)));
        _cachedChunkDirty = false;
    }

    private int GetChunkDataSize(int chunkIndex)
    {
        if (chunkIndex == 0)
            return FileFormat.GetChunk0DataCapacity(_chunkSizeBytes);

        var totalChunks = (int)_chunkCount;
        if (chunkIndex < totalChunks - 1)
            return FileFormat.GetChunkNDataCapacity(_chunkSizeBytes);

        // Last chunk may be smaller
        var chunk0Capacity = FileFormat.GetChunk0DataCapacity(_chunkSizeBytes);
        var chunkNCapacity = FileFormat.GetChunkNDataCapacity(_chunkSizeBytes);
        var dataInMiddleChunks = (ulong)((totalChunks - 2) * chunkNCapacity);
        var lastChunkSize = (long)(_plaintextLength - (ulong)chunk0Capacity - dataInMiddleChunks);
        return lastChunkSize <= 0 ? chunkNCapacity : (int)Math.Min(lastChunkSize, chunkNCapacity);
    }

    private int GetUserChunkCapacity(int chunkIndex)
    {
        if (chunkIndex == 0)
            return FileFormat.GetChunk0DataCapacity(_chunkSizeBytes);
        return FileFormat.GetChunkNDataCapacity(_chunkSizeBytes);
    }

    private void EnsureChunkLoaded(int chunkIndex)
    {
        if (_cachedChunkIndex == chunkIndex)
            return;

        FlushCachedChunk();

        if (chunkIndex >= (int)_chunkCount)
        {
            _cachedChunkData = new byte[GetUserChunkCapacity(chunkIndex)];
            _cachedChunkIndex = chunkIndex;
            _cachedChunkDirty = false;
            return;
        }

        _cachedChunkData = DecryptChunk(chunkIndex);
        _cachedChunkIndex = chunkIndex;
        _cachedChunkDirty = false;
    }

    public override bool CanRead => (_access & FileAccess.Read) != 0;
    public override bool CanSeek => true;
    public override bool CanWrite => (_access & FileAccess.Write) != 0;
    public override long Length => (long)_plaintextLength;

    public override long Position
    {
        get => _position;
        set
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(value));
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateBufferArgs(buffer, offset, count);
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!CanRead) throw new InvalidOperationException("Stream is not readable.");
        if (_header is null || buffer.Length == 0 || _position >= (long)_plaintextLength)
            return 0;

        var totalRead = 0;
        var remaining = buffer.Length;

        while (remaining > 0 && _position < (long)_plaintextLength)
        {
            var (chunkIndex, chunkOffset) = MapPosition(_position);
            EnsureChunkLoaded(chunkIndex);

            var available = _cachedChunkData!.Length - chunkOffset;
            var toRead = Math.Min(available, remaining);
            toRead = (int)Math.Min(toRead, (long)_plaintextLength - _position);

            _cachedChunkData.AsSpan(chunkOffset, toRead).CopyTo(buffer.Slice(totalRead, toRead));
            _position += toRead;
            totalRead += toRead;
            remaining -= toRead;
        }

        return totalRead;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateBufferArgs(buffer, offset, count);
        return await ReadAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!CanRead) throw new InvalidOperationException("Stream is not readable.");
        if (_header is null || buffer.Length == 0 || _position >= (long)_plaintextLength)
            return 0;

        var totalRead = 0;
        var remaining = buffer.Length;

        while (remaining > 0 && _position < (long)_plaintextLength)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (chunkIndex, chunkOffset) = MapPosition(_position);
            EnsureChunkLoaded(chunkIndex);

            var available = _cachedChunkData!.Length - chunkOffset;
            var toRead = Math.Min(available, remaining);
            toRead = (int)Math.Min(toRead, (long)_plaintextLength - _position);

            _cachedChunkData.AsSpan(chunkOffset, toRead).CopyTo(buffer.Span.Slice(totalRead, toRead));
            _position += toRead;
            totalRead += toRead;
            remaining -= toRead;
        }

        return totalRead;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        ValidateBufferArgs(buffer, offset, count);
        Write(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!CanWrite) throw new InvalidOperationException("Stream is not writable.");
        if (buffer.Length == 0) return;

        var written = 0;
        while (written < buffer.Length)
        {
            var (chunkIndex, chunkOffset) = MapPosition(_position);
            EnsureChunkLoaded(chunkIndex);

            var capacity = GetUserChunkCapacity(chunkIndex);
            var available = capacity - chunkOffset;
            var toWrite = Math.Min(available, buffer.Length - written);

            buffer.Slice(written, toWrite).CopyTo(_cachedChunkData.AsSpan(chunkOffset, toWrite));
            _cachedChunkDirty = true;
            _position += toWrite;
            written += toWrite;

            var newLength = Math.Max((long)_plaintextLength, _position);
            _plaintextLength = (ulong)newLength;
            _chunkCount = CalculateChunkCount(newLength);
        }
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateBufferArgs(buffer, offset, count);
        await WriteAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!CanWrite) throw new InvalidOperationException("Stream is not writable.");
        if (buffer.Length == 0) return;

        var written = 0;
        while (written < buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (chunkIndex, chunkOffset) = MapPosition(_position);
            EnsureChunkLoaded(chunkIndex);

            var capacity = GetUserChunkCapacity(chunkIndex);
            var available = capacity - chunkOffset;
            var toWrite = Math.Min(available, buffer.Length - written);

            buffer.Span.Slice(written, toWrite).CopyTo(_cachedChunkData.AsSpan(chunkOffset, toWrite));
            _cachedChunkDirty = true;
            _position += toWrite;
            written += toWrite;

            var newLength = Math.Max((long)_plaintextLength, _position);
            _plaintextLength = (ulong)newLength;
            _chunkCount = CalculateChunkCount(newLength);
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var newPosition = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => (long)_plaintextLength + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        if (newPosition < 0)
            throw new IOException("Attempted to seek before beginning of stream.");
        _position = newPosition;
        return _position;
    }

    public override void Flush()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        FlushCachedChunk();
        WriteChunk0();
        _fileStream.Flush();
    }

    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        FlushCachedChunk();
        WriteChunk0();
        await _fileStream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public override void SetLength(long value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!CanWrite) throw new InvalidOperationException("Stream is not writable.");
        if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));

        _plaintextLength = (ulong)value;
        _chunkCount = CalculateChunkCount(value);
        if (_position > value)
            _position = value;
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            if (CanWrite)
            {
                FlushCachedChunk();
                WriteChunk0();
            }
            _fileStream.Dispose();
            _disposed = true;
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            if (CanWrite)
            {
                FlushCachedChunk();
                WriteChunk0();
            }
            await _fileStream.DisposeAsync().ConfigureAwait(false);
            _disposed = true;
        }
        await base.DisposeAsync().ConfigureAwait(false);
    }

    public void VerifyIntegrity()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_header is null) return;

        // Verify each chunk can be decrypted (AES-GCM auth check)
        for (int i = 0; i < (int)_chunkCount; i++)
        {
            try
            {
                var plaintext = DecryptChunk(i);
            }
            catch (CryptographicException)
            {
                throw new InvalidDataException($"Chunk {i} authentication failed. The file may be corrupted.");
            }
        }
    }

    /// <summary>
    /// Maps a plaintext position to (chunkIndex, offsetWithinChunk).
    /// </summary>
    private (int chunkIndex, int offset) MapPosition(long position)
    {
        var chunk0Capacity = FileFormat.GetChunk0DataCapacity(_chunkSizeBytes);
        var chunkNCapacity = FileFormat.GetChunkNDataCapacity(_chunkSizeBytes);

        if (position < chunk0Capacity)
            return (0, (int)position);

        var remaining = position - chunk0Capacity;
        var chunkIndex = 1 + (int)(remaining / chunkNCapacity);
        var offset = (int)(remaining % chunkNCapacity);
        return (chunkIndex, offset);
    }

    /// <summary>
    /// Calculates the number of chunks needed for the given plaintext length.
    /// </summary>
    private uint CalculateChunkCount(long plaintextLength)
    {
        if (plaintextLength <= 0) return 0;

        var chunk0Capacity = FileFormat.GetChunk0DataCapacity(_chunkSizeBytes);
        if (plaintextLength <= chunk0Capacity) return 1;

        var chunkNCapacity = FileFormat.GetChunkNDataCapacity(_chunkSizeBytes);
        var remaining = plaintextLength - chunk0Capacity;
        return 1 + (uint)((remaining + chunkNCapacity - 1) / chunkNCapacity);
    }

    private static void ValidateBufferArgs(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        if (offset + count > buffer.Length) throw new ArgumentException("Invalid offset and count.");
    }

    private static Proto.ChunkSize ConvertChunkSize(ChunkSize size) => size switch
    {
        ChunkSize.Size4K => Proto.ChunkSize.Size4K,
        ChunkSize.Size8K => Proto.ChunkSize.Size8K,
        ChunkSize.Size16K => Proto.ChunkSize.Size16K,
        ChunkSize.Size32K => Proto.ChunkSize.Size32K,
        ChunkSize.Size64K => Proto.ChunkSize.Size64K,
        ChunkSize.Size128K => Proto.ChunkSize.Size128K,
        _ => throw new ArgumentOutOfRangeException(nameof(size))
    };
}
