namespace CipheredFileStream.IO.Exceptions;

/// <summary>
/// Thrown when an encrypted file has a format version newer than the library supports.
/// </summary>
public class EncryptedFileVersionException : Exception
{
    /// <summary>Version found in the file header.</summary>
    public ushort FileVersion { get; }

    /// <summary>Maximum version this library supports.</summary>
    public ushort MaxSupportedVersion { get; }

    /// <summary>File path, if known.</summary>
    public string? FilePath { get; }

    public EncryptedFileVersionException()
        : base("The encrypted file has an unsupported format version.") { }

    public EncryptedFileVersionException(string message)
        : base(message) { }

    public EncryptedFileVersionException(string message, Exception innerException)
        : base(message, innerException) { }

    public EncryptedFileVersionException(ushort fileVersion, ushort maxSupportedVersion, string? filePath = null)
        : base(BuildMessage(fileVersion, maxSupportedVersion, filePath))
    {
        FileVersion = fileVersion;
        MaxSupportedVersion = maxSupportedVersion;
        FilePath = filePath;
    }

    private static string BuildMessage(ushort fileVersion, ushort maxSupportedVersion, string? filePath)
    {
        var msg = $"Encrypted file format version 0x{fileVersion:X4} is not supported (max supported: 0x{maxSupportedVersion:X4}).";
        if (filePath is not null)
            msg += $" File: {filePath}";
        return msg;
    }
}
