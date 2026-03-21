namespace CipheredFileStream.IO.Exceptions;

/// <summary>
/// Thrown when an encrypted file fails authentication, integrity, or structural validation.
/// </summary>
public class EncryptedFileCorruptException : Exception
{
    /// <summary>Block index where corruption was detected, if applicable.</summary>
    public int? BlockIndex { get; }

    /// <summary>File path of the corrupted file, if known.</summary>
    public string? FilePath { get; }

    public EncryptedFileCorruptException()
        : base("The encrypted file is corrupted or was tampered with.") { }

    public EncryptedFileCorruptException(string message)
        : base(message) { }

    public EncryptedFileCorruptException(string message, Exception innerException)
        : base(message, innerException) { }

    public EncryptedFileCorruptException(string message, int blockIndex, string? filePath = null)
        : base(message)
    {
        BlockIndex = blockIndex;
        FilePath = filePath;
    }

    public static EncryptedFileCorruptException BlockAuthenticationFailed(int blockIndex, string? filePath = null)
        => new($"Block {blockIndex} authentication failed. The file may be corrupted or tampered with.", blockIndex, filePath);

    public static EncryptedFileCorruptException InvalidMagicBytes(string? filePath = null)
        => new($"Invalid magic bytes. Not a valid CipheredFileStream file.{(filePath is not null ? $" File: {filePath}" : "")}");

    public static EncryptedFileCorruptException IntegrityHashMismatch(string? filePath = null)
        => new($"File integrity hash mismatch. The file may be corrupted or tampered with.{(filePath is not null ? $" File: {filePath}" : "")}");
}
