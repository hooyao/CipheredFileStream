namespace CipheredFileStream.IO;

/// <summary>
/// Information read from an encrypted file's cleartext header.
/// Returned by <see cref="CipheredFileStreamFactory.ReadFileHeader"/>.
/// Allows callers to inspect the KDF method and parameters before providing a key or password.
/// </summary>
public readonly struct FileHeaderInfo
{
    /// <summary>File format version.</summary>
    public ushort FormatVersion { get; init; }

    /// <summary>Block size exponent (12–17).</summary>
    public int BlockSizeExponent { get; init; }

    /// <summary>Encryption algorithm ID byte.</summary>
    public byte AlgorithmId { get; init; }

    /// <summary>Key derivation method used when the file was created.</summary>
    public KdfMethod KdfMethod { get; init; }

    /// <summary>
    /// PBKDF2 salt (16 bytes). Null when <see cref="KdfMethod"/> is <see cref="IO.KdfMethod.None"/>.
    /// </summary>
    public byte[]? Salt { get; init; }

    /// <summary>
    /// PBKDF2 iteration count. Zero when <see cref="KdfMethod"/> is <see cref="IO.KdfMethod.None"/>.
    /// </summary>
    public uint KdfIterations { get; init; }
}
