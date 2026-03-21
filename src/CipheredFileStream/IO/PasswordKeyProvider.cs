using System.Security.Cryptography;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.IO;

/// <summary>
/// Derives a 32-byte encryption key from a password using PBKDF2-SHA256.
/// The derived key and password bytes are securely zeroed on disposal.
/// </summary>
public sealed class PasswordKeyProvider : IKeyProvider
{
    public const int DefaultIterations = 600_000;

    private byte[]? _key;
    private bool _disposed;

    /// <summary>PBKDF2 salt (16 bytes).</summary>
    public byte[] Salt { get; }

    /// <summary>PBKDF2 iteration count.</summary>
    public uint Iterations { get; }

    /// <summary>
    /// Creates a new provider for creating new files (generates random salt).
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="iterations">PBKDF2 iteration count. Default: 600,000.</param>
    public PasswordKeyProvider(ReadOnlySpan<char> password, int iterations = DefaultIterations)
    {
        if (password.IsEmpty)
            throw new ArgumentException("Password cannot be empty.", nameof(password));
        if (iterations < 1)
            throw new ArgumentOutOfRangeException(nameof(iterations));

        Salt = RandomNumberGenerator.GetBytes(EncryptedFileFormat.SaltSize);
        Iterations = (uint)iterations;
        _key = Rfc2898DeriveBytes.Pbkdf2(
            password, Salt, iterations, HashAlgorithmName.SHA256, EncryptedFileFormat.KeySize);
    }

    /// <summary>
    /// Creates a provider for opening existing files (uses salt and iterations from header).
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="salt">The 16-byte salt from the file header.</param>
    /// <param name="iterations">The iteration count from the file header.</param>
    public PasswordKeyProvider(ReadOnlySpan<char> password, byte[] salt, uint iterations)
    {
        if (password.IsEmpty)
            throw new ArgumentException("Password cannot be empty.", nameof(password));
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length != EncryptedFileFormat.SaltSize)
            throw new ArgumentException($"Salt must be {EncryptedFileFormat.SaltSize} bytes.", nameof(salt));
        if (iterations < 1)
            throw new ArgumentOutOfRangeException(nameof(iterations));

        Salt = (byte[])salt.Clone();
        Iterations = iterations;
        _key = Rfc2898DeriveBytes.Pbkdf2(
            password, Salt, (int)iterations, HashAlgorithmName.SHA256, EncryptedFileFormat.KeySize);
    }

    public byte[] GetKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _key!;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_key is not null)
            {
                Array.Clear(_key);
                _key = null;
            }
            _disposed = true;
        }
    }
}
