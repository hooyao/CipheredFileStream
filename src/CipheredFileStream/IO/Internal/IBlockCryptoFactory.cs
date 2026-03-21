namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Creates <see cref="IBlockCrypto"/> instances. Workers each get their own instance.
/// Also serves as the algorithm registry for auto-detection on file open.
/// </summary>
internal interface IBlockCryptoFactory
{
    /// <summary>
    /// The algorithm ID of the default (configured) algorithm for new files.
    /// </summary>
    byte DefaultAlgorithmId { get; }

    /// <summary>
    /// Creates a new <see cref="IBlockCrypto"/> instance for the configured default algorithm.
    /// Each call returns a fresh instance (workers must not share).
    /// </summary>
    /// <param name="maxCiphertextSize">Maximum ciphertext size for pre-allocating buffers.</param>
    IBlockCrypto Create(int maxCiphertextSize);

    /// <summary>
    /// Creates a new <see cref="IBlockCrypto"/> instance for the specified algorithm ID.
    /// Used when opening existing files (algorithm auto-detection from header).
    /// </summary>
    /// <param name="algorithmId">Algorithm ID byte from the cleartext header.</param>
    /// <param name="maxCiphertextSize">Maximum ciphertext size for pre-allocating buffers.</param>
    IBlockCrypto CreateForAlgorithm(byte algorithmId, int maxCiphertextSize);

    /// <summary>
    /// Returns the ciphertext overhead for the specified algorithm ID.
    /// Used by <see cref="BlockLayout"/> to compute PayloadCapacity.
    /// </summary>
    int GetCiphertextOverhead(byte algorithmId);
}
