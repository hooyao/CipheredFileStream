namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Block-level encrypt/decrypt with pre-allocated buffers.
/// NOT thread-safe: each worker creates its own instance.
/// Implementations MUST pre-allocate all buffers in the constructor.
/// </summary>
internal interface IBlockCrypto : IDisposable
{
    /// <summary>
    /// Unique algorithm identifier stored in the cleartext header.
    /// </summary>
    byte AlgorithmId { get; }

    /// <summary>
    /// Fixed ciphertext overhead in bytes added to every block.
    /// For GCM: 12 (nonce) + 16 (tag) = 28 bytes. No padding.
    /// </summary>
    int CiphertextOverhead { get; }

    /// <summary>
    /// Size of the integrity tag produced by Encrypt/Decrypt, in bytes (always 32).
    /// </summary>
    int IntegrityTagSize { get; }

    /// <summary>
    /// Encrypts plaintext into a pre-allocated output buffer and produces an integrity tag.
    /// </summary>
    /// <param name="key">Encryption key (32 bytes).</param>
    /// <param name="plaintext">Source plaintext buffer.</param>
    /// <param name="plaintextOffset">Offset into plaintext.</param>
    /// <param name="plaintextCount">Number of plaintext bytes.</param>
    /// <param name="aad">Additional authenticated data (8-byte block index, little-endian).</param>
    /// <param name="ciphertext">Destination ciphertext buffer (caller-provided, pre-allocated).</param>
    /// <param name="ciphertextOffset">Offset into destination.</param>
    /// <param name="integrityTag">Destination for the 32-byte integrity tag (caller-provided).</param>
    /// <returns>Number of ciphertext bytes written.</returns>
    int Encrypt(
        byte[] key,
        byte[] plaintext, int plaintextOffset, int plaintextCount,
        ReadOnlySpan<byte> aad,
        byte[] ciphertext, int ciphertextOffset,
        Span<byte> integrityTag);

    /// <summary>
    /// Decrypts ciphertext into a pre-allocated output buffer.
    /// Throws or returns -1 on authentication failure.
    /// </summary>
    /// <param name="key">Encryption key (32 bytes).</param>
    /// <param name="ciphertext">Source ciphertext buffer.</param>
    /// <param name="ciphertextOffset">Offset into ciphertext.</param>
    /// <param name="ciphertextCount">Number of ciphertext bytes.</param>
    /// <param name="aad">Additional authenticated data (8-byte block index, little-endian).</param>
    /// <param name="plaintext">Destination plaintext buffer (caller-provided, pre-allocated).</param>
    /// <param name="plaintextOffset">Offset into destination.</param>
    /// <param name="integrityTag">Destination for the 32-byte integrity tag extracted during decryption.</param>
    /// <returns>Number of plaintext bytes written, or -1 on authentication failure.</returns>
    int Decrypt(
        byte[] key,
        byte[] ciphertext, int ciphertextOffset, int ciphertextCount,
        ReadOnlySpan<byte> aad,
        byte[] plaintext, int plaintextOffset,
        Span<byte> integrityTag);

    /// <summary>
    /// Computes the exact ciphertext size for a given plaintext size.
    /// </summary>
    int GetCiphertextSize(int plaintextSize);

    /// <summary>
    /// Computes the maximum plaintext size that fits in the given ciphertext budget.
    /// </summary>
    int GetMaxPlaintextSize(int ciphertextSize);
}
