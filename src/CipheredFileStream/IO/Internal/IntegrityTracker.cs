using System.Runtime.CompilerServices;

namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Tracks file integrity using XOR of per-block integrity tags.
/// Algorithm-agnostic: receives 32-byte tags directly from callers
/// (produced by <see cref="IBlockCrypto.Encrypt"/>/<see cref="IBlockCrypto.Decrypt"/>).
/// Provides O(1) updates when individual blocks are modified.
/// </summary>
internal sealed class IntegrityTracker
{
    private readonly byte[] _integrityHash;
    private readonly Dictionary<int, byte[]> _blockHashes;

    public IntegrityTracker()
    {
        _integrityHash = new byte[EncryptedFileFormat.IntegrityHashSize];
        _blockHashes = new Dictionary<int, byte[]>();
    }

    public IntegrityTracker(byte[] existingHash)
    {
        if (existingHash.Length != EncryptedFileFormat.IntegrityHashSize)
            throw new ArgumentException(
                $"Integrity hash must be {EncryptedFileFormat.IntegrityHashSize} bytes.",
                nameof(existingHash));

        _integrityHash = new byte[EncryptedFileFormat.IntegrityHashSize];
        Array.Copy(existingHash, _integrityHash, EncryptedFileFormat.IntegrityHashSize);
        _blockHashes = new Dictionary<int, byte[]>();
    }

    /// <summary>
    /// Updates the integrity hash when a block is modified.
    /// </summary>
    /// <param name="blockIndex">The block index being modified.</param>
    /// <param name="newTag">The 32-byte integrity tag from IBlockCrypto.Encrypt.</param>
    public void UpdateIntegrity(int blockIndex, byte[] newTag)
    {
        byte[]? oldTag = _blockHashes.GetValueOrDefault(blockIndex);

        if (oldTag is not null)
        {
            for (int i = 0; i < EncryptedFileFormat.IntegrityHashSize; i++)
                _integrityHash[i] ^= (byte)(oldTag[i] ^ newTag[i]);
        }
        else
        {
            for (int i = 0; i < EncryptedFileFormat.IntegrityHashSize; i++)
                _integrityHash[i] ^= newTag[i];
        }

        _blockHashes[blockIndex] = (byte[])newTag.Clone();
    }

    /// <summary>
    /// Records a block's integrity tag without modifying the running hash.
    /// Used when loading existing blocks from disk.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void RecordBlockHash(int blockIndex, byte[] tag)
    {
        _blockHashes[blockIndex] = (byte[])tag.Clone();
    }

    /// <summary>
    /// Gets the cached hash for a block, if available.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte[]? GetCachedBlockHash(int blockIndex)
        => _blockHashes.TryGetValue(blockIndex, out byte[]? hash) ? hash : null;

    /// <summary>
    /// Removes a block's contribution from the integrity hash (used during truncation).
    /// </summary>
    public void RemoveBlock(int blockIndex)
    {
        if (_blockHashes.TryGetValue(blockIndex, out byte[]? existingHash))
        {
            for (int i = 0; i < EncryptedFileFormat.IntegrityHashSize; i++)
                _integrityHash[i] ^= existingHash[i];

            _blockHashes.Remove(blockIndex);
        }
    }

    /// <summary>
    /// Gets a copy of the current integrity hash.
    /// </summary>
    public byte[] GetIntegrityHash()
    {
        byte[] copy = new byte[EncryptedFileFormat.IntegrityHashSize];
        Array.Copy(_integrityHash, copy, EncryptedFileFormat.IntegrityHashSize);
        return copy;
    }

    /// <summary>
    /// Sets the integrity hash directly. Used when loading from a file header.
    /// </summary>
    public void SetIntegrityHash(byte[] hash)
    {
        if (hash.Length != EncryptedFileFormat.IntegrityHashSize)
            throw new ArgumentException(
                $"Integrity hash must be {EncryptedFileFormat.IntegrityHashSize} bytes.",
                nameof(hash));

        Array.Copy(hash, _integrityHash, EncryptedFileFormat.IntegrityHashSize);
    }

    /// <summary>
    /// Resets the tracker to initial state.
    /// </summary>
    public void Reset()
    {
        Array.Clear(_integrityHash, 0, _integrityHash.Length);
        _blockHashes.Clear();
    }
}
