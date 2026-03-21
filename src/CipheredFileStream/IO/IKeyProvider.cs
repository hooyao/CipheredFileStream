namespace CipheredFileStream.IO;

/// <summary>
/// Provides a 32-byte (256-bit) encryption key.
/// </summary>
public interface IKeyProvider : IDisposable
{
    /// <summary>
    /// Returns the 32-byte encryption key.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The provider has been disposed.</exception>
    byte[] GetKey();
}
