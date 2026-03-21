using System.Runtime.CompilerServices;

namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Accumulates plaintext writes into block-sized slots, encrypts full slots
/// (optionally in parallel), and writes them to disk in bulk IO operations.
/// Activated only when AccessPattern is Sequential.
/// </summary>
internal sealed class WriteBehindBuffer : IDisposable
{
    private const int DefaultBufferSize = 1024 * 1024; // 1MB
    private const int MinSlotCount = 2;

    private readonly Stream _underlyingStream;
    private readonly byte[] _key;
    private readonly BlockLayout _layout;
    private readonly IntegrityTracker _integrityTracker;
    private readonly PositionMapper _positionMapper;
    private readonly string? _filePath;

    private readonly byte[][] _slots;
    private readonly int _slotCount;
    private readonly byte[] _rawBuffer;

    // Per-worker crypto resources
    private readonly CryptoWorker[] _workers;
    private readonly int _concurrency;

    // Per-slot: ciphertext lengths and integrity tags (filled during parallel encrypt)
    private readonly int[] _ctLengths;
    private readonly byte[][] _slotTags;

    // Buffer state
    private int _startBlockIndex = -1;
    private int _writeCursor;
    private int _offsetInSlot;
    private int _dirtySlots;
    private int _maxBlockIndex;

    public WriteBehindBuffer(
        Stream underlyingStream,
        byte[] key,
        BlockLayout layout,
        IntegrityTracker integrityTracker,
        PositionMapper positionMapper,
        IBlockCryptoFactory cryptoFactory,
        int bufferSize,
        int concurrency,
        string? filePath = null)
    {
        _underlyingStream = underlyingStream;
        _key = key;
        _layout = layout;
        _integrityTracker = integrityTracker;
        _positionMapper = positionMapper;
        _filePath = filePath;

        int effectiveBufferSize = bufferSize > 0 ? bufferSize : DefaultBufferSize;
        _slotCount = Math.Max(MinSlotCount, effectiveBufferSize / layout.BlockSize);

        _slots = new byte[_slotCount][];
        _slotTags = new byte[_slotCount][];
        for (int i = 0; i < _slotCount; i++)
        {
            _slots[i] = new byte[layout.PayloadCapacity];
            _slotTags[i] = new byte[EncryptedFileFormat.IntegrityHashSize];
        }

        _rawBuffer = new byte[_slotCount * layout.BlockSize];
        _ctLengths = new int[_slotCount];

        _concurrency = Math.Max(1, concurrency);
        _workers = new CryptoWorker[_concurrency];
        for (int i = 0; i < _concurrency; i++)
            _workers[i] = new CryptoWorker(layout, cryptoFactory);
    }

    public int MaxBlockIndex => _maxBlockIndex;

    public bool HasPendingData
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _dirtySlots > 0 || _offsetInSlot > 0;
    }

    public void Write(long cleartextPosition, byte[] buffer, int offset, int count)
    {
        if (count == 0) return;

        int remaining = count;
        int sourceOffset = offset;
        long currentPos = cleartextPosition;

        while (remaining > 0)
        {
            (int blockIndex, int offsetInPayload) = _positionMapper.MapPosition(currentPos);

            if (_startBlockIndex < 0)
            {
                _startBlockIndex = blockIndex;
                _writeCursor = 0;
                _offsetInSlot = offsetInPayload;
                _dirtySlots = 0;
                InitializeSlot(0);
            }
            else if (blockIndex < _startBlockIndex || blockIndex >= _startBlockIndex + _slotCount)
            {
                FlushBatch();
                _startBlockIndex = blockIndex;
                _writeCursor = 0;
                _offsetInSlot = offsetInPayload;
                _dirtySlots = 0;
                InitializeSlot(0);
            }

            int slotIndex = blockIndex - _startBlockIndex;

            while (_writeCursor < slotIndex)
            {
                _writeCursor++;
                _dirtySlots = Math.Max(_dirtySlots, _writeCursor);
                if (_writeCursor < _slotCount)
                    InitializeSlot(_writeCursor);
                _offsetInSlot = _positionMapper.GetBlockDataStart(_startBlockIndex + _writeCursor);
            }

            int dataCapacity = _positionMapper.GetBlockDataCapacity(blockIndex);
            int dataStart = _positionMapper.GetBlockDataStart(blockIndex);
            int positionInData = offsetInPayload - dataStart;
            int availableInSlot = dataCapacity - positionInData;
            int toWrite = Math.Min(remaining, availableInSlot);

            Array.Copy(buffer, sourceOffset, _slots[slotIndex], offsetInPayload, toWrite);

            sourceOffset += toWrite;
            currentPos += toWrite;
            remaining -= toWrite;
            _offsetInSlot = offsetInPayload + toWrite;

            if (blockIndex > _maxBlockIndex)
                _maxBlockIndex = blockIndex;

            if (_offsetInSlot >= dataStart + dataCapacity)
            {
                _dirtySlots = Math.Max(_dirtySlots, slotIndex + 1);

                if (_dirtySlots >= _slotCount)
                {
                    FlushBatch();
                    int nextBlockIndex = blockIndex + 1;
                    _startBlockIndex = nextBlockIndex;
                    _writeCursor = 0;
                    _offsetInSlot = _positionMapper.GetBlockDataStart(nextBlockIndex);
                    _dirtySlots = 0;
                    if (remaining > 0)
                        InitializeSlot(0);
                }
                else
                {
                    _writeCursor = slotIndex + 1;
                    if (_writeCursor < _slotCount && remaining > 0)
                    {
                        InitializeSlot(_writeCursor);
                        _offsetInSlot = _positionMapper.GetBlockDataStart(_startBlockIndex + _writeCursor);
                    }
                }
            }
        }
    }

    private void InitializeSlot(int slotIndex)
        => Array.Clear(_slots[slotIndex], 0, _slots[slotIndex].Length);

    /// <summary>
    /// Phase 1: Parallel encrypt all dirty slots (tags captured per-slot).
    /// Phase 2: Serial integrity update using captured tags.
    /// Phase 3: Bulk IO write.
    /// </summary>
    private void FlushBatch()
    {
        if (_dirtySlots <= 0 && _offsetInSlot <= 0)
            return;

        int slotsToFlush = _dirtySlots;
        if (_writeCursor >= _dirtySlots && _offsetInSlot > 0)
            slotsToFlush = _writeCursor + 1;

        if (slotsToFlush <= 0)
            return;

        // === Phase 1: Encrypt (parallel when concurrency > 1) ===
        if (_concurrency <= 1 || slotsToFlush < _concurrency * 2)
        {
            for (int i = 0; i < slotsToFlush; i++)
                EncryptAndAssemble(i, _startBlockIndex + i, ref _workers[0]);
        }
        else
        {
            int partitions = Math.Min(_concurrency, slotsToFlush);
            Exception? workerException = null;
            int pendingWorkers = partitions - 1;
            int abort = 0;

            for (int p = 1; p < partitions; p++)
            {
                int partIdx = p;
                int pStart = slotsToFlush * partIdx / partitions;
                int pEnd = slotsToFlush * (partIdx + 1) / partitions;
                ThreadPool.UnsafeQueueUserWorkItem(_ =>
                {
                    try
                    {
                        ref var worker = ref _workers[partIdx];
                        for (int i = pStart; i < pEnd; i++)
                        {
                            if (Volatile.Read(ref abort) != 0) break;
                            EncryptAndAssemble(i, _startBlockIndex + i, ref worker);
                        }
                    }
                    catch (Exception ex)
                    {
                        Interlocked.CompareExchange(ref workerException, ex, null);
                        Volatile.Write(ref abort, 1);
                    }
                    finally
                    {
                        if (Interlocked.Decrement(ref pendingWorkers) == 0)
                            lock (_workers) { Monitor.Pulse(_workers); }
                    }
                }, null);
            }

            Exception? mainException = null;
            {
                int pEnd = slotsToFlush * 1 / partitions;
                try
                {
                    for (int i = 0; i < pEnd; i++)
                    {
                        if (Volatile.Read(ref abort) != 0) break;
                        EncryptAndAssemble(i, _startBlockIndex + i, ref _workers[0]);
                    }
                }
                catch (Exception ex)
                {
                    mainException = ex;
                    Volatile.Write(ref abort, 1);
                }
            }

            if (pendingWorkers > 0)
                lock (_workers) { while (pendingWorkers > 0) Monitor.Wait(_workers); }

            if (mainException != null) throw mainException;
            if (workerException != null) throw workerException;
        }

        // === Phase 2: Serial integrity update using per-slot tags ===
        for (int i = 0; i < slotsToFlush; i++)
        {
            int blockIndex = _startBlockIndex + i;
            _integrityTracker.UpdateIntegrity(blockIndex, _slotTags[i]);
        }

        // === Phase 3: Bulk write to disk ===
        int rawTotal = slotsToFlush * _layout.BlockSize;
        long physicalOffset = _positionMapper.GetPhysicalOffset(_startBlockIndex);
        _underlyingStream.Position = physicalOffset;

        int writeStart = 0;
        if (_startBlockIndex == 0)
        {
            writeStart = EncryptedFileFormat.CleartextHeaderSize;
            _underlyingStream.Position = physicalOffset + EncryptedFileFormat.CleartextHeaderSize;
        }

        _underlyingStream.Write(_rawBuffer, writeStart, rawTotal - writeStart);

        _dirtySlots = 0;
    }

    private void EncryptAndAssemble(int slotIndex, int blockIndex, ref CryptoWorker w)
    {
        BitConverter.TryWriteBytes(w.AadBuffer, (long)blockIndex);

        int plaintextSize = _layout.PayloadCapacity;
        int ctLen = w.Crypto.Encrypt(
            _key, _slots[slotIndex], 0, plaintextSize, w.AadBuffer, w.CtBuffer, 0, w.IntegrityTagBuffer);

        if (ctLen < 0)
            throw new InvalidOperationException($"Encryption failed for block {blockIndex}.");

        _ctLengths[slotIndex] = ctLen;

        // Copy integrity tag to per-slot tag buffer (thread-safe: non-overlapping)
        Array.Copy(w.IntegrityTagBuffer, 0, _slotTags[slotIndex], 0, EncryptedFileFormat.IntegrityHashSize);

        // Assemble into _rawBuffer: [lengthPrefix][ciphertext][padding]
        int blockStart = slotIndex * _layout.BlockSize;
        int prefixStart = blockStart;
        if (blockIndex == 0)
            prefixStart += EncryptedFileFormat.CleartextHeaderSize;

        BitConverter.TryWriteBytes(_rawBuffer.AsSpan(prefixStart), (uint)ctLen);

        int ctStart = prefixStart + _layout.CiphertextLengthPrefixSize;
        Array.Copy(w.CtBuffer, 0, _rawBuffer, ctStart, ctLen);

        int written = ctStart + ctLen - blockStart;
        int paddingNeeded = _layout.BlockSize - written;
        if (paddingNeeded > 0)
            Array.Clear(_rawBuffer, blockStart + written, paddingNeeded);
    }

    public void FlushRemaining()
    {
        if (_startBlockIndex < 0) return;
        FlushBatch();
        _startBlockIndex = -1;
        _writeCursor = 0;
        _offsetInSlot = 0;
        _dirtySlots = 0;
    }

    public void Dispose()
    {
        foreach (ref var w in _workers.AsSpan())
            w.Dispose();
        Array.Clear(_rawBuffer);
        for (int i = 0; i < _slots.Length; i++)
            Array.Clear(_slots[i]);
    }

    private struct CryptoWorker : IDisposable
    {
        public readonly IBlockCrypto Crypto;
        public readonly byte[] CtBuffer;
        public readonly byte[] AadBuffer;
        public readonly byte[] IntegrityTagBuffer;

        public CryptoWorker(BlockLayout layout, IBlockCryptoFactory factory)
        {
            Crypto = factory.Create(layout.BlockNMaxCiphertextSize);
            CtBuffer = new byte[layout.BlockNMaxCiphertextSize];
            AadBuffer = new byte[EncryptedFileFormat.AadSize];
            IntegrityTagBuffer = new byte[EncryptedFileFormat.IntegrityHashSize];
        }

        public void Dispose()
        {
            Crypto?.Dispose();
            if (CtBuffer != null) Array.Clear(CtBuffer);
            if (IntegrityTagBuffer != null) Array.Clear(IntegrityTagBuffer);
        }
    }
}
