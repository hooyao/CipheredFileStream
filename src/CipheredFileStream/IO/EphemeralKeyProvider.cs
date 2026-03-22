using System.Security.Cryptography;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.IO;

/// <summary>
/// Generates a cryptographically random 32-byte key on construction.
/// The key is securely zeroed on disposal.
/// </summary>
public sealed class EphemeralKeyProvider : IKeyProvider
{
    private readonly byte[] _key;
    private bool _disposed;

    public EphemeralKeyProvider()
    {
        _key = new byte[EncryptedFileFormat.KeySize];
        RandomNumberGenerator.Fill(_key);
    }

    public byte[] GetKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _key;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Array.Clear(_key);
            _disposed = true;
        }
    }
}
