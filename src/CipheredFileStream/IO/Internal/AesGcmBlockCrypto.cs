using System.Security.Cryptography;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.IO.Internal;

/// <summary>
/// AES-256-GCM block encryption. Algorithm ID 0x01.
/// Ciphertext envelope: [12B nonce][ciphertext][16B auth tag].
/// Overhead: 28 bytes (12 nonce + 16 tag), NO padding.
/// Integrity tag: GCM auth tag (16 bytes) zero-padded to 32 bytes.
///
/// NOT thread-safe. Each worker creates its own instance.
/// All buffers pre-allocated in the constructor.
/// </summary>
internal sealed class AesGcmBlockCrypto : IBlockCrypto
{
    public const byte AlgorithmIdConst = 0x01;
    public const int Overhead = NonceSize + TagSize;  // 28

    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int IntegrityTagSizeConst = 32;

    // Pre-allocated buffers (reused per call)
    private readonly byte[] _nonce;        // 12 bytes
    private readonly byte[] _tag;          // 16 bytes

    public byte AlgorithmId => AlgorithmIdConst;
    public int CiphertextOverhead => Overhead;
    public int IntegrityTagSize => IntegrityTagSizeConst;

    public AesGcmBlockCrypto(int maxCiphertextSize = 0)
    {
        _nonce = new byte[NonceSize];
        _tag = new byte[TagSize];
    }

    public int Encrypt(
        byte[] key,
        byte[] plaintext, int plaintextOffset, int plaintextCount,
        ReadOnlySpan<byte> aad,
        byte[] ciphertext, int ciphertextOffset,
        Span<byte> integrityTag)
    {
        // 1. Generate random 12-byte nonce
        RandomNumberGenerator.Fill(_nonce);

        // 2. Write nonce to output: [nonce][ciphertext][tag]
        _nonce.CopyTo(ciphertext.AsSpan(ciphertextOffset));

        // 3. AES-GCM encrypt
        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Encrypt(
            _nonce,
            plaintext.AsSpan(plaintextOffset, plaintextCount),
            ciphertext.AsSpan(ciphertextOffset + NonceSize, plaintextCount),
            _tag,
            aad);

        // 4. Write tag after ciphertext
        _tag.CopyTo(ciphertext.AsSpan(ciphertextOffset + NonceSize + plaintextCount));

        // 5. Produce 32-byte integrity tag: GCM tag zero-padded to 32
        integrityTag.Clear();
        _tag.CopyTo(integrityTag);

        return NonceSize + plaintextCount + TagSize;
    }

    public int Decrypt(
        byte[] key,
        byte[] ciphertext, int ciphertextOffset, int ciphertextCount,
        ReadOnlySpan<byte> aad,
        byte[] plaintext, int plaintextOffset,
        Span<byte> integrityTag)
    {
        if (ciphertextCount < NonceSize + TagSize)
            return -1;

        int payloadSize = ciphertextCount - NonceSize - TagSize;

        // 1. Extract nonce
        ciphertext.AsSpan(ciphertextOffset, NonceSize).CopyTo(_nonce);

        // 2. Extract tag
        ciphertext.AsSpan(ciphertextOffset + NonceSize + payloadSize, TagSize).CopyTo(_tag);

        // 3. Decrypt and authenticate
        try
        {
            using var aesGcm = new AesGcm(key, TagSize);
            aesGcm.Decrypt(
                _nonce,
                ciphertext.AsSpan(ciphertextOffset + NonceSize, payloadSize),
                _tag,
                plaintext.AsSpan(plaintextOffset, payloadSize),
                aad);
        }
        catch (CryptographicException)
        {
            return -1;  // Authentication failed
        }

        // 4. Produce 32-byte integrity tag: GCM tag zero-padded to 32
        integrityTag.Clear();
        _tag.CopyTo(integrityTag);

        return payloadSize;
    }

    public int GetCiphertextSize(int plaintextSize)
        => NonceSize + plaintextSize + TagSize;

    public int GetMaxPlaintextSize(int ciphertextSize)
        => ciphertextSize - NonceSize - TagSize;

    public void Dispose()
    {
        Array.Clear(_nonce);
        Array.Clear(_tag);
    }
}
