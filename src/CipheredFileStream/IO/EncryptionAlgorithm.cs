namespace CipheredFileStream.IO;

/// <summary>
/// Encryption algorithm selection for new files.
/// Existing files auto-detect the algorithm from the header's algorithm ID byte.
/// </summary>
public enum EncryptionAlgorithm : byte
{
    /// <summary>AES-256-GCM. Algorithm ID 0x01.</summary>
    AesGcm = 0x01,

    // Future algorithms:
    // AesCbcHmacSha512 = 0x02,
}
