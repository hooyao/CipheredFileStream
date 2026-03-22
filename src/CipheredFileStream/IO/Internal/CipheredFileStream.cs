using Google.Protobuf;
using CipheredFileStream.IO.Protos;
using CipheredFileStream.IO.Exceptions;

namespace CipheredFileStream.IO.Internal;

/// <summary>
/// A stream that transparently encrypts data on write and decrypts on read.
/// Extends <see cref="Stream"/> to serve as a drop-in replacement for <see cref="FileStream"/>.
/// </summary>
internal sealed class CipheredFileStream : Stream
{
    private const int DefaultConcurrency = 2;
    private static readonly byte[] GapZeroBuffer = new byte[4096];

    private readonly Stream _underlyingStream;
    private readonly byte[] _key;
    private BlockManager _blockManager = null!;
    private readonly IntegrityTracker _integrityTracker;
    private PositionMapper _positionMapper = null!;
    private BlockLayout _layout = null!;
    private readonly IBlockCryptoFactory _cryptoFactory;
    private readonly byte _algorithmId;
    private readonly KdfMethod _kdfMethod;
    private readonly byte[]? _salt;
    private readonly uint _kdfIterations;
    private readonly string? _filePath;
    private readonly bool _canRead;
    private readonly bool _canWrite;

    private readonly AccessPattern _accessPattern;
    private readonly int _bufferSize;
    private readonly int _concurrency;
    private ReadAheadBuffer? _readBuffer;
    private WriteBehindBuffer? _writeBuffer;
    private bool _sequentialFallback; // true = ring buffer disabled, using BlockManager

    private long _cleartextLength;
    private long _position;
    private int _blockCount;
    private bool _disposed;
    private bool _headerDirty;
    private readonly byte[] _singleByteBuf = new byte[1];

    /// <summary>
    /// Initializes a new instance of the <see cref="CipheredFileStream"/> class.
    /// </summary>
    /// <param name="underlyingStream">The underlying stream (FileStream).</param>
    /// <param name="key">The 32-byte encryption key.</param>
    /// <param name="mode">The file mode used to open the stream.</param>
    /// <param name="access">The file access mode.</param>
    /// <param name="layout">Block layout for new files. Ignored when opening existing files (read from header).</param>
    /// <param name="cryptoFactory">Factory for creating per-worker IBlockCrypto instances.</param>
    /// <param name="algorithmId">Algorithm ID byte for new files.</param>
    /// <param name="kdfMethod">Key derivation method for new files.</param>
    /// <param name="salt">PBKDF2 salt (16 bytes) for new files. Null when kdfMethod is None.</param>
    /// <param name="kdfIterations">PBKDF2 iteration count for new files. Zero when kdfMethod is None.</param>
    /// <param name="accessPattern">Sequential or RandomAccess hint.</param>
    /// <param name="bufferSize">Buffer size hint for sequential buffers.</param>
    /// <param name="concurrency">Parallel encryption/decryption worker count.</param>
    /// <param name="filePath">Optional file path for error messages.</param>
    internal CipheredFileStream(
        Stream underlyingStream,
        byte[] key,
        FileMode mode,
        FileAccess access,
        BlockLayout layout,
        IBlockCryptoFactory cryptoFactory,
        byte algorithmId,
        KdfMethod kdfMethod = KdfMethod.None,
        byte[]? salt = null,
        uint kdfIterations = 0,
        AccessPattern accessPattern = AccessPattern.Sequential,
        int bufferSize = 0,
        int concurrency = 0,
        string? filePath = null)
    {
        _underlyingStream = underlyingStream;
        _key = new byte[key.Length];
        Array.Copy(key, _key, key.Length);
        _cryptoFactory = cryptoFactory;
        _algorithmId = algorithmId;
        _kdfMethod = kdfMethod;
        _salt = salt is not null ? (byte[])salt.Clone() : null;
        _kdfIterations = kdfIterations;
        _filePath = filePath;
        _canRead = access.HasFlag(FileAccess.Read);
        _canWrite = access.HasFlag(FileAccess.Write);
        _accessPattern = accessPattern;
        _bufferSize = bufferSize;
        _concurrency = concurrency > 0 ? concurrency : DefaultConcurrency;
        _concurrency = Math.Min(_concurrency, Environment.ProcessorCount);

        _integrityTracker = new IntegrityTracker();

        if (mode == FileMode.Create || mode == FileMode.CreateNew || mode == FileMode.Truncate ||
            (mode == FileMode.OpenOrCreate && _underlyingStream.Length == 0))
        {
            // Initialize new file with provided layout
            _layout = layout;
            _positionMapper = new PositionMapper(_layout);
            _blockManager = new BlockManager(_underlyingStream, _key, _integrityTracker, _layout, _positionMapper, _cryptoFactory, _filePath);
            InitializeNewFile();
        }
        else
        {
            // Open existing file -- layout is determined from file header
            ReadHeader();
        }

        if (mode == FileMode.Append)
        {
            _position = _cleartextLength;
        }
    }

    /// <inheritdoc/>
    public override bool CanRead => !_disposed && _canRead;

    /// <inheritdoc/>
    public override bool CanWrite => !_disposed && _canWrite;

    /// <inheritdoc/>
    public override bool CanSeek => !_disposed && _underlyingStream.CanSeek;

    /// <inheritdoc/>
    public override long Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _cleartextLength;
        }
    }

    /// <inheritdoc/>
    public override long Position
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _position;
        }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Position cannot be negative.");
            }

            // Flush pending write data before changing position (same as Seek).
            if (_writeBuffer != null && _writeBuffer.HasPendingData)
            {
                FlushAndResetBuffers();
            }

            _position = value;
        }
    }

    #region Header Management

    /// <summary>
    /// Initializes a new encrypted file with default header.
    /// </summary>
    private void InitializeNewFile()
    {
        _cleartextLength = 0;
        _blockCount = 1;
        _integrityTracker.Reset();

        // Write cleartext header
        WriteCleartextHeader();

        // Initialize block 0 with empty header
        _blockManager.EnsureBlock(0, isNewBlock: true);

        // Write Protobuf header to block 0 payload
        WriteProtobufHeaderToPayload();
        _blockManager.MarkDirty();
        _blockManager.FlushBlock();

        _headerDirty = false;
    }

    /// <summary>
    /// Writes the 32-byte cleartext header including AlgorithmId, KdfMethod, Salt, and KdfIterations.
    /// </summary>
    private void WriteCleartextHeader()
    {
        _underlyingStream.Position = 0;

        Span<byte> header = stackalloc byte[EncryptedFileFormat.CleartextHeaderSize];
        header.Clear();
        BitConverter.TryWriteBytes(header, EncryptedFileFormat.MagicBytes);
        BitConverter.TryWriteBytes(header.Slice(2), EncryptedFileFormat.FormatVersion);
        header[EncryptedFileFormat.BlockSizeExponentOffset] = (byte)_layout.BlockSizeExponent;
        header[EncryptedFileFormat.AlgorithmIdOffset] = _algorithmId;
        header[EncryptedFileFormat.KdfMethodOffset] = (byte)_kdfMethod;
        // Byte 7 is reserved (zero)

        // Write salt (16 bytes at offset 8)
        if (_salt is not null && _salt.Length == EncryptedFileFormat.SaltSize)
        {
            _salt.AsSpan().CopyTo(header.Slice(EncryptedFileFormat.SaltOffset, EncryptedFileFormat.SaltSize));
        }

        // Write KDF iterations (uint32 LE at offset 24)
        BitConverter.TryWriteBytes(header.Slice(EncryptedFileFormat.KdfIterationsOffset), _kdfIterations);

        // Bytes 28-31 are reserved (zeros)

        _underlyingStream.Write(header);
    }

    /// <summary>
    /// Reads and validates the file header, determining block layout from it.
    /// </summary>
    private void ReadHeader()
    {
        _underlyingStream.Position = 0;

        // Read cleartext header
        Span<byte> cleartextHeader = stackalloc byte[EncryptedFileFormat.CleartextHeaderSize];
        int bytesRead = _underlyingStream.Read(cleartextHeader);

        if (bytesRead < EncryptedFileFormat.CleartextHeaderSize)
        {
            throw EncryptedFileCorruptException.InvalidMagicBytes(_filePath);
        }

        // Validate magic bytes
        ushort magic = BitConverter.ToUInt16(cleartextHeader);
        if (magic != EncryptedFileFormat.MagicBytes)
        {
            throw EncryptedFileCorruptException.InvalidMagicBytes(_filePath);
        }

        // Validate version
        ushort version = BitConverter.ToUInt16(cleartextHeader.Slice(2));
        if (version < EncryptedFileFormat.FormatVersion || version > EncryptedFileFormat.MaxSupportedVersion)
        {
            throw new EncryptedFileVersionException(version, EncryptedFileFormat.MaxSupportedVersion, _filePath);
        }

        // Read block size exponent from header byte[4]
        int blockSizeExponent = cleartextHeader[EncryptedFileFormat.BlockSizeExponentOffset];
        if (blockSizeExponent < EncryptedFileFormat.MinBlockSizeExponent ||
            blockSizeExponent > EncryptedFileFormat.MaxBlockSizeExponent)
        {
            throw new EncryptedFileCorruptException(
                $"Invalid block size exponent {blockSizeExponent} (must be {EncryptedFileFormat.MinBlockSizeExponent}-{EncryptedFileFormat.MaxBlockSizeExponent}).",
                0, _filePath);
        }

        // Read algorithm ID from header byte[5]
        byte algorithmId = cleartextHeader[EncryptedFileFormat.AlgorithmIdOffset];

        // Read KDF method from header byte[6]
        // (CipheredFileStream itself doesn't derive keys -- that's the factory's job)
        // byte kdfMethod = cleartextHeader[EncryptedFileFormat.KdfMethodOffset];

        // Read salt from header bytes[8..24]
        // byte[] salt = cleartextHeader.Slice(EncryptedFileFormat.SaltOffset, EncryptedFileFormat.SaltSize).ToArray();

        // Read KDF iterations from header bytes[24..28]
        // uint kdfIterations = BitConverter.ToUInt32(cleartextHeader.Slice(EncryptedFileFormat.KdfIterationsOffset));

        // Construct BlockLayout using the algorithm's overhead
        int ciphertextOverhead = _cryptoFactory.GetCiphertextOverhead(algorithmId);
        _layout = new BlockLayout(blockSizeExponent, ciphertextOverhead);
        _positionMapper = new PositionMapper(_layout);
        _blockManager?.Dispose();
        _blockManager = new BlockManager(_underlyingStream, _key, _integrityTracker, _layout, _positionMapper, _cryptoFactory, _filePath);

        // Load and decrypt block 0
        _blockManager.EnsureBlock(0);

        // Parse Protobuf header from payload
        ReadProtobufHeaderFromPayload();
    }

    /// <summary>
    /// Reads the Protobuf header from block 0 payload.
    /// </summary>
    private void ReadProtobufHeaderFromPayload()
    {
        Span<byte> payload = _blockManager.GetCachedPayloadSpan();

        // Read header length prefix
        ushort headerLength = BitConverter.ToUInt16(payload);

        if (headerLength == 0 || headerLength > EncryptedFileFormat.ProtobufHeaderMaxSize)
        {
            throw new EncryptedFileCorruptException(
                $"Invalid header length: {headerLength} (max: {EncryptedFileFormat.ProtobufHeaderMaxSize}).",
                0,
                _filePath);
        }

        // Parse Protobuf header
        Span<byte> headerBytes = payload.Slice(EncryptedFileFormat.HeaderLengthPrefixSize, headerLength);
        EncryptedFileHeader? header = EncryptedFileHeader.Parser.ParseFrom(headerBytes.ToArray());

        _cleartextLength = header.CleartextLength;
        _blockCount = header.BlockCount;

        // Set integrity hash
        if (header.IntegrityHash.Length == EncryptedFileFormat.IntegrityHashSize)
        {
            _integrityTracker.SetIntegrityHash(header.IntegrityHash.ToByteArray());
        }
    }

    /// <summary>
    /// Writes the Protobuf header to block 0 payload.
    /// </summary>
    private void WriteProtobufHeaderToPayload()
    {
        EncryptedFileHeader header = new EncryptedFileHeader
        {
            CleartextLength = _cleartextLength,
            IntegrityHash = ByteString.CopyFrom(_integrityTracker.GetIntegrityHash()),
            BlockCount = _blockCount,
            HeaderVersion = EncryptedFileFormat.HeaderSchemaVersion
        };

        byte[] headerBytes = header.ToByteArray();

        // Validate header fits within maximum expected size
        if (headerBytes.Length > EncryptedFileFormat.ProtobufHeaderMaxSize)
        {
            throw new InvalidOperationException(
                $"Protobuf header too large: {headerBytes.Length} bytes (max: {EncryptedFileFormat.ProtobufHeaderMaxSize}).");
        }

        Span<byte> payload = _blockManager.GetCachedPayloadSpan();

        // Write header length prefix
        BitConverter.TryWriteBytes(payload, (ushort)headerBytes.Length);

        // Write header bytes
        headerBytes.CopyTo(payload.Slice(EncryptedFileFormat.HeaderLengthPrefixSize));
    }

    /// <summary>
    /// Updates the header in block 0 and writes it to disk.
    /// </summary>
    private void WriteHeader()
    {
        // Ensure block 0 exists
        bool isNewBlock = _blockCount == 0;
        if (isNewBlock)
            _blockCount = 1;

        // Always write the cleartext header (32 bytes at offset 0).
        // Cheap and ensures header is present after truncate-to-zero scenarios.
        WriteCleartextHeader();

        _blockManager.EnsureBlock(0, isNewBlock: isNewBlock);

        // Update Protobuf header
        WriteProtobufHeaderToPayload();
        _blockManager.MarkDirty();
        _blockManager.FlushBlock();

        _headerDirty = false;
    }

    #endregion

    #region Read Operations

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateReadArguments(buffer, offset, count);

        if (_position >= _cleartextLength)
        {
            return 0; // EOF
        }

        // Sequential fast path -- delegate to ReadAheadBuffer
        if (_accessPattern == AccessPattern.Sequential && _canRead && !_sequentialFallback)
        {
            _readBuffer ??= new ReadAheadBuffer(
                _underlyingStream, _key, _layout, _integrityTracker, _positionMapper, _cryptoFactory, _bufferSize, _concurrency, _filePath);

            int bytesRead = _readBuffer.Read(_position, buffer, offset, count, _cleartextLength);
            _position += bytesRead;
            return bytesRead;
        }

        // RandomAccess/Fallback path -- BlockManager logic
        int totalRead = 0;
        int remaining = (int)Math.Min(count, _cleartextLength - _position);

        while (remaining > 0)
        {
            (int blockIndex, int offsetInPayload) = _positionMapper.MapPosition(_position);

            // Ensure the block is loaded
            _blockManager.EnsureBlock(blockIndex);

            // Calculate how much we can read from this block
            int dataStart = _positionMapper.GetBlockDataStart(blockIndex);
            int dataCapacity = _positionMapper.GetBlockDataCapacity(blockIndex);
            int positionInData = offsetInPayload - dataStart;
            int availableInBlock = dataCapacity - positionInData;
            int toRead = Math.Min(remaining, availableInBlock);

            // Read from cache
            int bytesRead = _blockManager.ReadFromCache(offsetInPayload, buffer, offset + totalRead, toRead);

            totalRead += bytesRead;
            _position += bytesRead;
            remaining -= bytesRead;

            if (bytesRead == 0)
            {
                break; // No more data available
            }
        }

        return totalRead;
    }

    /// <inheritdoc/>
    public override int ReadByte()
    {
        int bytesRead = Read(_singleByteBuf, 0, 1);
        return bytesRead == 0 ? -1 : _singleByteBuf[0];
    }

    /// <inheritdoc/>
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Read(buffer, offset, count));
    }

    /// <inheritdoc/>
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // CipheredFileStream's IO is CPU-bound (crypto), not truly async.
        if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out ArraySegment<byte> segment))
        {
            return ValueTask.FromResult(Read(segment.Array!, segment.Offset, segment.Count));
        }
        else
        {
            byte[] temp = new byte[buffer.Length];
            int read = Read(temp, 0, buffer.Length);
            if (read > 0)
                temp.AsSpan(0, read).CopyTo(buffer.Span);
            return ValueTask.FromResult(read);
        }
    }

    private void ValidateReadArguments(byte[] buffer, int offset, int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_canRead)
        {
            throw new NotSupportedException("Stream does not support reading.");
        }

        ArgumentNullException.ThrowIfNull(buffer);

        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), "Offset cannot be negative.");
        }

        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Count cannot be negative.");
        }

        if (buffer.Length - offset < count)
        {
            throw new ArgumentException("Buffer is too small for the requested read.");
        }
    }

    #endregion

    #region Write Operations

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count)
    {
        ValidateWriteArguments(buffer, offset, count);

        if (count == 0)
        {
            return;
        }

        // Sequential fast path -- delegate to WriteBehindBuffer
        if (_accessPattern == AccessPattern.Sequential && _canWrite && !_sequentialFallback)
        {
            bool canUseSequentialWrite = _position == _cleartextLength && !IsMidBlockAppend();

            if (!canUseSequentialWrite)
            {
                FallBackToBlockManager();
                // Fall through to BlockManager path below
            }
            else
            {

            _writeBuffer ??= new WriteBehindBuffer(
                _underlyingStream, _key, _layout, _integrityTracker, _positionMapper, _cryptoFactory, _bufferSize, _concurrency, _filePath);

            _writeBuffer.Write(_position, buffer, offset, count);
            _position += count;

            // Update length and block count
            if (_position > _cleartextLength)
            {
                _cleartextLength = _position;
                _headerDirty = true;
            }

            int newBlockCount = _writeBuffer.MaxBlockIndex + 1;
            if (newBlockCount > _blockCount)
            {
                _blockCount = newBlockCount;
                _headerDirty = true;
            }

            return;
            } // end else (sequential append path)
        }

        // RandomAccess/Fallback path -- BlockManager logic
        // Handle writing beyond current length (creates gap filled with zeros)
        if (_position > _cleartextLength)
        {
            FillGap(_cleartextLength, _position - _cleartextLength);
        }

        int totalWritten = 0;
        int remaining = count;

        while (remaining > 0)
        {
            (int blockIndex, int offsetInPayload) = _positionMapper.MapPosition(_position);

            // Check if we need a new block
            bool isNewBlock = blockIndex >= _blockCount;
            if (isNewBlock)
            {
                _blockCount = blockIndex + 1;
                _headerDirty = true;
            }

            // Ensure the block is loaded (or initialized if new)
            _blockManager.EnsureBlock(blockIndex, isNewBlock);

            // Calculate how much we can write to this block
            int dataStart = _positionMapper.GetBlockDataStart(blockIndex);
            int dataCapacity = _positionMapper.GetBlockDataCapacity(blockIndex);
            int positionInData = offsetInPayload - dataStart;
            int availableInBlock = dataCapacity - positionInData;
            int toWrite = Math.Min(remaining, availableInBlock);

            // Write to cache
            _blockManager.WriteToCache(offsetInPayload, buffer, offset + totalWritten, toWrite);

            totalWritten += toWrite;
            _position += toWrite;
            remaining -= toWrite;
        }

        // Update length if we extended the file
        if (_position > _cleartextLength)
        {
            _cleartextLength = _position;
            _headerDirty = true;
        }
    }

    /// <inheritdoc/>
    public override void WriteByte(byte value)
    {
        _singleByteBuf[0] = value;
        Write(_singleByteBuf, 0, 1);
    }

    /// <inheritdoc/>
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Write(buffer, offset, count);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // CipheredFileStream's IO is CPU-bound (crypto), not truly async.
        if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment))
        {
            Write(segment.Array!, segment.Offset, segment.Count);
        }
        else
        {
            byte[] temp = buffer.ToArray();
            Write(temp, 0, temp.Length);
        }
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Fills a gap in the file with zeros (BlockManager path).
    /// </summary>
    private void FillGap(long start, long length)
    {
        byte[] zeros = GapZeroBuffer;
        long remaining = length;

        _position = start;

        while (remaining > 0)
        {
            int toWrite = (int)Math.Min(zeros.Length, remaining);
            Write(zeros, 0, toWrite);
            remaining -= toWrite;
        }
    }

    private void ValidateWriteArguments(byte[] buffer, int offset, int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_canWrite)
        {
            throw new NotSupportedException("Stream does not support writing.");
        }

        ArgumentNullException.ThrowIfNull(buffer);

        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), "Offset cannot be negative.");
        }

        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Count cannot be negative.");
        }

        if (buffer.Length - offset < count)
        {
            throw new ArgumentException("Buffer is too small for the requested write.");
        }
    }

    /// <summary>
    /// Falls back from ring buffer to BlockManager permanently.
    /// Only used for operations that fundamentally break sequential assumptions
    /// (overwrite writes, SetLength).
    /// </summary>
    private void FallBackToBlockManager()
    {
        if (_sequentialFallback)
            return;

        FlushAndResetBuffers();
        _sequentialFallback = true;
    }

    /// <summary>
    /// Flushes any pending ring buffer data to disk and resets buffer state,
    /// but does NOT permanently disable ring buffers. After this call,
    /// subsequent sequential reads/writes can still use ring buffers.
    /// </summary>
    private void FlushAndResetBuffers()
    {
        if (_writeBuffer != null && _writeBuffer.HasPendingData)
        {
            _writeBuffer.FlushRemaining();
        }

        // Invalidate BlockManager cache since ring buffer may have written blocks
        if (_writeBuffer != null || _readBuffer != null)
        {
            _blockManager.InvalidateCache();
        }
    }

    /// <summary>
    /// Detects mid-block append after Flush: position is at EOF but in the middle of
    /// an existing block. WriteBehindBuffer would zero-initialize the slot, losing the
    /// block's existing data. In this case we must fall back to BlockManager.
    /// </summary>
    private bool IsMidBlockAppend()
    {
        if (_cleartextLength <= 0) return false;
        var (blockIndex, offsetInPayload) = _positionMapper.MapPosition(_position);
        int dataStart = _positionMapper.GetBlockDataStart(blockIndex);
        return offsetInPayload != dataStart && blockIndex < _blockCount;
    }

    #endregion

    #region Seek and SetLength

    /// <inheritdoc/>
    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        long newPosition = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _cleartextLength + offset,
            _ => throw new ArgumentException("Invalid seek origin.", nameof(origin))
        };

        if (newPosition < 0)
        {
            throw new IOException("Cannot seek to a negative position.");
        }

        // Flush pending write data before seeking so subsequent reads see it on disk.
        if (_writeBuffer != null && _writeBuffer.HasPendingData)
        {
            FlushAndResetBuffers();
        }

        _position = newPosition;
        return _position;
    }

    /// <inheritdoc/>
    public override void SetLength(long value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_canWrite)
        {
            throw new NotSupportedException("Stream does not support writing.");
        }

        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Length cannot be negative.");
        }

        // SetLength is not supported by ring buffer -- fall back to BlockManager
        FallBackToBlockManager();

        if (value == _cleartextLength)
        {
            return;
        }

        if (value < _cleartextLength)
        {
            // Truncate
            TruncateFile(value);
        }
        else
        {
            // Extend with zeros
            long currentPosition = _position;
            FillGap(_cleartextLength, value - _cleartextLength);
            _position = currentPosition;
        }
    }

    /// <summary>
    /// Truncates the file to the specified length.
    /// </summary>
    private void TruncateFile(long newLength)
    {
        // Calculate new block count
        int newBlockCount = _positionMapper.GetBlockCount(newLength);

        // Flush current block if it's being truncated
        _blockManager.FlushBlock();

        // Remove integrity hash contributions from blocks being truncated.
        for (int i = newBlockCount; i < _blockCount; i++)
        {
            _integrityTracker.RemoveBlock(i);
        }

        // Update length
        _cleartextLength = newLength;
        _blockCount = newBlockCount;
        _headerDirty = true;

        // Truncate underlying file
        long physicalLength = (long)newBlockCount * _layout.BlockSize;
        _underlyingStream.SetLength(physicalLength);

        // If truncated to 0 blocks, ensure cleartext header will be rewritten
        // when the next write or Flush/Dispose creates block 0.
        if (newBlockCount == 0)
        {
            _integrityTracker.Reset();
        }

        // Adjust position if beyond new length
        if (_position > _cleartextLength)
        {
            _position = _cleartextLength;
        }

        // Invalidate cache if cached block no longer exists
        if (_blockManager.CachedBlockIndex >= newBlockCount)
        {
            _blockManager.InvalidateCache();
        }
    }

    #endregion

    #region Flush and Dispose

    /// <inheritdoc/>
    public override void Flush()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Flush write-behind buffer if active
        if (_writeBuffer != null)
        {
            if (_writeBuffer.HasPendingData)
            {
                _writeBuffer.FlushRemaining();
            }

            // Flush any dirty BlockManager block (from fallback writes)
            _blockManager?.FlushBlock();

            // Invalidate BlockManager cache since WriteBehindBuffer may have written
            // blocks that BlockManager still has stale cached copies of.
            _blockManager?.InvalidateCache();
        }
        else
        {
            // No write-behind buffer -- just flush BlockManager
            _blockManager?.FlushBlock();
        }

        // Update header if needed
        if (_headerDirty)
        {
            WriteHeader();
        }

        _underlyingStream.Flush();
    }

    /// <inheritdoc/>
    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Flush();
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            try
            {
                if (_canWrite)
                {
                    Flush();
                }
            }
            finally
            {
                _disposed = true;
                _readBuffer?.Dispose();
                _writeBuffer?.Dispose();
                _blockManager?.Dispose();
                _underlyingStream.Dispose();
                Array.Clear(_key);
            }
        }
        else
        {
            _disposed = true;
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc/>
    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            if (_canWrite)
            {
                await FlushAsync(CancellationToken.None);
            }
        }
        finally
        {
            _disposed = true;
            _readBuffer?.Dispose();
            _writeBuffer?.Dispose();
            _blockManager?.Dispose();
            await _underlyingStream.DisposeAsync();
            Array.Clear(_key);
            GC.SuppressFinalize(this);
        }
    }

    #endregion
}
