namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Maps cleartext byte positions to (blockIndex, offsetInPayload).
/// Accounts for block 0's header overhead (87 bytes).
/// </summary>
internal sealed class PositionMapper
{
    private readonly BlockLayout _layout;

    public PositionMapper(BlockLayout layout)
    {
        _layout = layout;
    }

    /// <summary>
    /// Maps a cleartext byte position to the block index and offset within the block's payload.
    /// </summary>
    public (int blockIndex, int offsetInPayload) MapPosition(long cleartextPosition)
    {
        if (cleartextPosition < _layout.Block0DataCapacity)
            return (0, _layout.Block0DataStart + (int)cleartextPosition);

        long adjusted = cleartextPosition - _layout.Block0DataCapacity;
        int blockIndex = 1 + (int)(adjusted / _layout.BlockNDataCapacity);
        int offset = (int)(adjusted % _layout.BlockNDataCapacity);
        return (blockIndex, offset);
    }

    /// <summary>
    /// Returns the user data capacity for the given block index.
    /// </summary>
    public int GetBlockDataCapacity(int blockIndex)
        => blockIndex == 0 ? _layout.Block0DataCapacity : _layout.BlockNDataCapacity;

    /// <summary>
    /// Returns the physical file offset where the given block starts.
    /// </summary>
    public long GetPhysicalOffset(int blockIndex)
        => (long)blockIndex * _layout.BlockSize;

    /// <summary>
    /// Returns the offset where user data starts within the block's decrypted payload.
    /// </summary>
    public int GetBlockDataStart(int blockIndex)
        => blockIndex == 0 ? _layout.Block0DataStart : 0;

    /// <summary>
    /// Returns the cleartext byte position at the start of the given block's user data region.
    /// </summary>
    public long GetCleartextPositionForBlock(int blockIndex)
    {
        if (blockIndex == 0) return 0;
        return _layout.Block0DataCapacity + (long)(blockIndex - 1) * _layout.BlockNDataCapacity;
    }

    /// <summary>
    /// Calculates the total number of blocks needed to store the given cleartext length.
    /// </summary>
    public int GetBlockCount(long cleartextLength)
    {
        if (cleartextLength <= 0) return 0;
        if (cleartextLength <= _layout.Block0DataCapacity) return 1;

        long remaining = cleartextLength - _layout.Block0DataCapacity;
        return 1 + (int)((remaining + _layout.BlockNDataCapacity - 1) / _layout.BlockNDataCapacity);
    }
}
