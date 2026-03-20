using System.Security.Cryptography;

namespace CipheredFileStream;

public enum ChunkSize
{
    Size4K = 4096,
    Size8K = 8192,
    Size16K = 16384,
    Size32K = 32768,
    Size64K = 65536,
    Size128K = 131072
}

internal static class FileFormat
{
    public static readonly byte[] MagicNumber = "CIPHERED"u8.ToArray();  // 8 bytes cleartext
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;
    public const int MasterNonceSize = 12;
    public const int ChecksumSize = 32;
    public const int SaltSize = 16;
    public const int DefaultPbkdf2Iterations = 600_000;

    // Chunk 0 cleartext: 8 (magic) + 16 (salt) + 4 (ct length) = 28 bytes
    public const int Chunk0CleartextSize = 8 + SaltSize + 4;  // 28 bytes
    public const int CtLengthSize = 4;

    // Header metadata inside chunk 0 encrypted payload: 2 (hdr len) + 128 (protobuf max) + 8 (plaintext_length) + 4 (chunk_count) = 142
    public const int HeaderMetadataSize = 2 + 128 + 8 + 4;

    /// <summary>
    /// Chunk 0 data capacity: chunk_size - cleartext(28) - nonce(12) - tag(16) - metadata(142)
    /// </summary>
    public static int GetChunk0DataCapacity(int chunkSize)
        => chunkSize - Chunk0CleartextSize - NonceSize - TagSize - HeaderMetadataSize;

    /// <summary>
    /// Chunk N data capacity: chunk_size - ct_length(4) - nonce(12) - tag(16)
    /// </summary>
    public static int GetChunkNDataCapacity(int chunkSize)
        => chunkSize - CtLengthSize - NonceSize - TagSize;

    public static byte[] DeriveChunkNonce(byte[] masterNonce, uint chunkIndex)
    {
        var nonce = new byte[NonceSize];
        Array.Copy(masterNonce, 0, nonce, 0, 4);
        BitConverter.TryWriteBytes(nonce.AsSpan(4, 4), chunkIndex);
        Array.Copy(masterNonce, 4, nonce, 8, 4);
        return nonce;
    }

    public static byte[] ComputeChunkChecksum(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
    {
        using var sha256 = SHA256.Create();
        var totalLength = nonce.Length + ciphertext.Length + tag.Length;
        var buffer = new byte[totalLength];
        nonce.CopyTo(buffer);
        ciphertext.CopyTo(buffer.AsSpan(nonce.Length));
        tag.CopyTo(buffer.AsSpan(nonce.Length + ciphertext.Length));
        return sha256.ComputeHash(buffer);
    }

    public static void UpdateTotalChecksum(byte[] totalChecksum, byte[] oldChunkChecksum, byte[] newChunkChecksum)
    {
        for (int i = 0; i < ChecksumSize; i++)
        {
            totalChecksum[i] ^= oldChunkChecksum[i];
            totalChecksum[i] ^= newChunkChecksum[i];
        }
    }

    public static byte[] DeriveKeyFromPassword(ReadOnlySpan<char> password, byte[] salt, int iterations)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, KeySize);
    }
}
