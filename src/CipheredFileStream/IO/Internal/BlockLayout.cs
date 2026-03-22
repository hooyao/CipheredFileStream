namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Computes block geometry (payload capacity, data capacity, ciphertext sizes)
/// from a block size exponent and the crypto algorithm's overhead.
/// </summary>
internal sealed class BlockLayout
{
    /// <summary>Physical block size in bytes.</summary>
    public int BlockSize { get; }

    /// <summary>Block size exponent (12–17). BlockSize = 1 &lt;&lt; exponent.</summary>
    public int BlockSizeExponent { get; }

    /// <summary>Size of the ciphertext length prefix in bytes (always 4).</summary>
    public int CiphertextLengthPrefixSize { get; }

    /// <summary>Maximum ciphertext size in block 0 (after cleartext header and length prefix).</summary>
    public int Block0MaxCiphertextSize { get; }

    /// <summary>Maximum ciphertext size in blocks N >= 1 (after length prefix).</summary>
    public int BlockNMaxCiphertextSize { get; }

    /// <summary>
    /// Maximum decrypted payload size per block.
    /// For GCM: BlockNMaxCiphertextSize - 28 (nonce + tag).
    /// </summary>
    public int PayloadCapacity { get; }

    /// <summary>
    /// Offset where user data starts within block 0's payload (fixed at 87).
    /// </summary>
    public int Block0DataStart { get; }

    /// <summary>User data capacity of block 0 (PayloadCapacity - Block0DataStart).</summary>
    public int Block0DataCapacity { get; }

    /// <summary>User data capacity of blocks N >= 1 (equals PayloadCapacity).</summary>
    public int BlockNDataCapacity { get; }

    /// <param name="blockSizeExponent">Power-of-2 exponent (12–17).</param>
    /// <param name="ciphertextOverhead">From <see cref="IBlockCrypto.CiphertextOverhead"/>.</param>
    public BlockLayout(int blockSizeExponent, int ciphertextOverhead)
    {
        if (blockSizeExponent < EncryptedFileFormat.MinBlockSizeExponent ||
            blockSizeExponent > EncryptedFileFormat.MaxBlockSizeExponent)
        {
            throw new ArgumentOutOfRangeException(
                nameof(blockSizeExponent),
                $"Block size exponent must be between {EncryptedFileFormat.MinBlockSizeExponent} and {EncryptedFileFormat.MaxBlockSizeExponent}.");
        }

        BlockSizeExponent = blockSizeExponent;
        BlockSize = 1 << blockSizeExponent;
        CiphertextLengthPrefixSize = EncryptedFileFormat.CiphertextLengthPrefixSize;

        Block0MaxCiphertextSize = BlockSize - EncryptedFileFormat.CleartextHeaderSize - CiphertextLengthPrefixSize;
        BlockNMaxCiphertextSize = BlockSize - CiphertextLengthPrefixSize;

        // PayloadCapacity must fit within BOTH block 0 and block N.
        // Block 0 has less ciphertext space (cleartext header takes 32 bytes).
        // Use Block0MaxCiphertextSize as the constraint so all blocks share the same
        // decrypted payload size. Block N wastes (CleartextHeaderSize) bytes as padding.
        PayloadCapacity = Block0MaxCiphertextSize - ciphertextOverhead;

        Block0DataStart = EncryptedFileFormat.HeaderLengthPrefixSize + EncryptedFileFormat.ProtobufHeaderMaxSize;
        Block0DataCapacity = PayloadCapacity - Block0DataStart;
        BlockNDataCapacity = PayloadCapacity;
    }
}
