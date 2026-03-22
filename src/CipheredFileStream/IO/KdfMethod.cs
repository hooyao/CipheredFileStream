namespace CipheredFileStream.IO;

/// <summary>
/// Key derivation method used to produce the encryption key.
/// Stored in the cleartext header at offset 6.
/// </summary>
public enum KdfMethod : byte
{
    /// <summary>Direct key — no derivation. Salt and iterations are ignored.</summary>
    None = 0x00,

    /// <summary>PBKDF2 with SHA-256 hash. Salt (16 bytes) and iteration count stored in header.</summary>
    Pbkdf2Sha256 = 0x01,
}
