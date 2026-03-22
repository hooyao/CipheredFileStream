using System.Runtime.CompilerServices;
using CipheredFileStream.IO.Exceptions;

namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Bulk-reads multiple contiguous blocks in a single IO operation, decrypts them
/// (optionally in parallel), and serves subsequent Read calls from decrypted slots.
/// Activated only when AccessPattern is Sequential.
/// </summary>
internal sealed class ReadAheadBuffer : IDisposable
{
    private const int DefaultBufferSize = 1024 * 1024; // 1MB
    private const int MinSlotCount = 2;

    private readonly Stream _underlyingStream;
    private readonly byte[] _key;
    private readonly BlockLayout _layout;
    private readonly IntegrityTracker _integrityTracker;
    private readonly PositionMapper _positionMapper;
    private readonly string? _filePath;

    private readonly byte[] _rawBuffer;
    private readonly byte[][] _slots;
    private readonly int _slotCount;

    // Per-worker crypto resources
    private readonly CryptoWorker[] _workers;
    private readonly int _concurrency;

    // Per-slot integrity tags (filled during parallel decrypt, consumed serially after)
    private readonly byte[][] _slotTags;

    // Buffer state
    private int _startBlockIndex = -1;
    private int _validSlots;

    public ReadAheadBuffer(
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

        _rawBuffer = new byte[_slotCount * layout.BlockSize];
        _slots = new byte[_slotCount][];
        _slotTags = new byte[_slotCount][];
        for (int i = 0; i < _slotCount; i++)
        {
            _slots[i] = new byte[layout.PayloadCapacity];
            _slotTags[i] = new byte[EncryptedFileFormat.IntegrityHashSize];
        }

        _concurrency = Math.Max(1, concurrency);
        _workers = new CryptoWorker[_concurrency];
        for (int i = 0; i < _concurrency; i++)
            _workers[i] = new CryptoWorker(layout, cryptoFactory);
    }

    public int Read(long cleartextPosition, byte[] buffer, int offset, int count, long cleartextLength)
    {
        if (cleartextPosition >= cleartextLength)
            return 0;

        int remaining = (int)Math.Min(count, cleartextLength - cleartextPosition);
        int totalRead = 0;
        long currentPos = cleartextPosition;

        while (remaining > 0)
        {
            (int blockIndex, int offsetInPayload) = _positionMapper.MapPosition(currentPos);

            if (!IsBlockBuffered(blockIndex))
            {
                int maxBlockIndex = _positionMapper.GetBlockCount(cleartextLength) - 1;
                Fill(blockIndex, maxBlockIndex);
            }

            int slotIndex = blockIndex - _startBlockIndex;
            int dataStart = _positionMapper.GetBlockDataStart(blockIndex);
            int dataCapacity = _positionMapper.GetBlockDataCapacity(blockIndex);
            int positionInData = offsetInPayload - dataStart;
            int availableInBlock = dataCapacity - positionInData;
            int toRead = Math.Min(remaining, availableInBlock);

            if (toRead <= 0) break;

            Array.Copy(_slots[slotIndex], offsetInPayload, buffer, offset + totalRead, toRead);

            totalRead += toRead;
            currentPos += toRead;
            remaining -= toRead;
        }

        return totalRead;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool IsBlockBuffered(int blockIndex)
        => _startBlockIndex >= 0
           && blockIndex >= _startBlockIndex
           && blockIndex < _startBlockIndex + _validSlots;

    private void Fill(int startBlockIndex, int maxBlockIndex)
    {
        int blocksToRead = Math.Min(_slotCount, maxBlockIndex - startBlockIndex + 1);
        if (blocksToRead <= 0)
        {
            _startBlockIndex = startBlockIndex;
            _validSlots = 0;
            return;
        }

        // Bulk read from disk
        long physicalOffset = _positionMapper.GetPhysicalOffset(startBlockIndex);
        _underlyingStream.Position = physicalOffset;

        int totalBytesToRead = blocksToRead * _layout.BlockSize;
        int totalBytesRead = 0;
        while (totalBytesRead < totalBytesToRead)
        {
            int read = _underlyingStream.Read(_rawBuffer, totalBytesRead, totalBytesToRead - totalBytesRead);
            if (read == 0) break;
            totalBytesRead += read;
        }

        int actualBlocks = totalBytesRead / _layout.BlockSize;

        if (_concurrency <= 1 || actualBlocks < _concurrency * 2)
        {
            // Serial path
            for (int i = 0; i < actualBlocks; i++)
                DecryptBlock(startBlockIndex + i, i * _layout.BlockSize, _slots[i], _slotTags[i], ref _workers[0]);
        }
        else
        {
            // Parallel decrypt
            int partitions = Math.Min(_concurrency, actualBlocks);
            Exception? workerException = null;
            int pendingWorkers = partitions - 1;
            int abort = 0;

            for (int p = 1; p < partitions; p++)
            {
                int partIdx = p;
                int pStart = actualBlocks * partIdx / partitions;
                int pEnd = actualBlocks * (partIdx + 1) / partitions;
                ThreadPool.UnsafeQueueUserWorkItem(_ =>
                {
                    try
                    {
                        ref var worker = ref _workers[partIdx];
                        for (int i = pStart; i < pEnd; i++)
                        {
                            if (Volatile.Read(ref abort) != 0) break;
                            DecryptBlock(startBlockIndex + i, i * _layout.BlockSize, _slots[i], _slotTags[i], ref worker);
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

            // Main thread: partition 0
            Exception? mainException = null;
            {
                int pEnd = actualBlocks * 1 / partitions;
                try
                {
                    for (int i = 0; i < pEnd; i++)
                    {
                        if (Volatile.Read(ref abort) != 0) break;
                        DecryptBlock(startBlockIndex + i, i * _layout.BlockSize, _slots[i], _slotTags[i], ref _workers[0]);
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

        // Serial: record integrity tags
        for (int i = 0; i < actualBlocks; i++)
            _integrityTracker.RecordBlockHash(startBlockIndex + i, _slotTags[i]);

        _startBlockIndex = startBlockIndex;
        _validSlots = actualBlocks;
    }

    private void DecryptBlock(int blockIndex, int rawBufferOffset, byte[] targetSlot, byte[] targetTag, ref CryptoWorker w)
    {
        int prefixOffset = rawBufferOffset;
        if (blockIndex == 0)
            prefixOffset += EncryptedFileFormat.CleartextHeaderSize;

        int ciphertextLength = (int)BitConverter.ToUInt32(_rawBuffer, prefixOffset);
        int maxCiphertextSize = blockIndex == 0 ? _layout.Block0MaxCiphertextSize : _layout.BlockNMaxCiphertextSize;
        if (ciphertextLength <= 0 || ciphertextLength > maxCiphertextSize)
            throw new EncryptedFileCorruptException(
                $"Invalid ciphertext length {ciphertextLength} for block {blockIndex}.", blockIndex, _filePath);

        int ciphertextOffset = prefixOffset + _layout.CiphertextLengthPrefixSize;
        Array.Copy(_rawBuffer, ciphertextOffset, w.CtBuffer, 0, ciphertextLength);

        BitConverter.TryWriteBytes(w.AadBuffer, (long)blockIndex);

        int decryptedLength = w.Crypto.Decrypt(
            _key, w.CtBuffer, 0, ciphertextLength, w.AadBuffer, w.PtBuffer, 0, w.IntegrityTagBuffer);

        if (decryptedLength == -1)
            throw EncryptedFileCorruptException.BlockAuthenticationFailed(blockIndex, _filePath);

        Array.Copy(w.PtBuffer, 0, targetSlot, 0, decryptedLength);

        // Copy integrity tag to per-slot tag buffer (thread-safe: each slot is non-overlapping)
        Array.Copy(w.IntegrityTagBuffer, 0, targetTag, 0, EncryptedFileFormat.IntegrityHashSize);
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
        public readonly byte[] PtBuffer;
        public readonly byte[] AadBuffer;
        public readonly byte[] IntegrityTagBuffer;

        public CryptoWorker(BlockLayout layout, IBlockCryptoFactory factory)
        {
            Crypto = factory.Create(layout.BlockNMaxCiphertextSize);
            CtBuffer = new byte[layout.BlockNMaxCiphertextSize];
            PtBuffer = new byte[layout.BlockSize];
            AadBuffer = new byte[EncryptedFileFormat.AadSize];
            IntegrityTagBuffer = new byte[EncryptedFileFormat.IntegrityHashSize];
        }

        public void Dispose()
        {
            Crypto?.Dispose();
            if (PtBuffer != null) Array.Clear(PtBuffer);
            if (CtBuffer != null) Array.Clear(CtBuffer);
            if (IntegrityTagBuffer != null) Array.Clear(IntegrityTagBuffer);
        }
    }
}
