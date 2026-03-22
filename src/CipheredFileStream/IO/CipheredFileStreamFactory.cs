using System.Buffers.Binary;
using CipheredFileStream.IO.Exceptions;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.IO;

/// <summary>
/// Factory for creating encrypted file streams.
/// Manages the encryption key lifetime and constructs properly-configured
/// <see cref="CipheredFileStream"/> instances with the appropriate block layout,
/// crypto factory, and IO buffering strategy.
/// </summary>
public sealed class CipheredFileStreamFactory : ICipheredStreamFactory
{
    private readonly IKeyProvider? _keyProvider;
    private byte[]? _key;
    private bool _disposed;

    /// <summary>
    /// Creates a factory using a raw 32-byte encryption key.
    /// A defensive copy of the key is made; the caller may clear the original.
    /// </summary>
    /// <param name="key">The 32-byte AES-256 encryption key.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not 32 bytes.</exception>
    public CipheredFileStreamFactory(byte[] key)
    {
        ThrowHelper.ThrowIfNull(key, nameof(key));
        if (key.Length != EncryptedFileFormat.KeySize)
            throw new ArgumentException(
                $"Key must be exactly {EncryptedFileFormat.KeySize} bytes.", nameof(key));

        _key = (byte[])key.Clone();
    }

    /// <summary>
    /// Creates a factory using a key provider (e.g., <see cref="PasswordKeyProvider"/> or
    /// <see cref="EphemeralKeyProvider"/>). The provider is not disposed by the factory;
    /// the caller retains ownership.
    /// </summary>
    /// <param name="keyProvider">The key provider.</param>
    /// <exception cref="ArgumentNullException"><paramref name="keyProvider"/> is null.</exception>
    public CipheredFileStreamFactory(IKeyProvider keyProvider)
    {
        ThrowHelper.ThrowIfNull(keyProvider, nameof(keyProvider));
        _keyProvider = keyProvider;
        _key = (byte[])keyProvider.GetKey().Clone();
    }

    /// <summary>
    /// Reads the 32-byte cleartext header from an existing encrypted file
    /// and returns the parsed <see cref="FileHeaderInfo"/>.
    /// Useful for inspecting the KDF method and parameters before providing a key or password.
    /// </summary>
    /// <param name="path">Path to the encrypted file.</param>
    /// <returns>Parsed header information.</returns>
    /// <exception cref="EncryptedFileCorruptException">The file is too small or has invalid magic bytes.</exception>
    /// <exception cref="EncryptedFileVersionException">The file version is not supported.</exception>
    public static FileHeaderInfo ReadFileHeader(string path)
    {
        ThrowHelper.ThrowIfNullOrEmpty(path, nameof(path));

        var header = new byte[EncryptedFileFormat.CleartextHeaderSize];

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        int bytesRead = fs.Read(header, 0, header.Length);
        if (bytesRead < EncryptedFileFormat.CleartextHeaderSize)
            throw EncryptedFileCorruptException.InvalidMagicBytes(path);

        // Validate magic bytes
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(header);
        if (magic != EncryptedFileFormat.MagicBytes)
            throw EncryptedFileCorruptException.InvalidMagicBytes(path);

        // Validate version
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(2));
        if (version > EncryptedFileFormat.MaxSupportedVersion)
            throw new EncryptedFileVersionException(version, EncryptedFileFormat.MaxSupportedVersion, path);

        int blockSizeExponent = header[EncryptedFileFormat.BlockSizeExponentOffset];
        byte algorithmId = header[EncryptedFileFormat.AlgorithmIdOffset];
        var kdfMethod = (KdfMethod)header[EncryptedFileFormat.KdfMethodOffset];

        byte[]? salt = null;
        uint kdfIterations = 0;

        if (kdfMethod == KdfMethod.Pbkdf2Sha256)
        {
            salt = header.AsSpan(EncryptedFileFormat.SaltOffset, EncryptedFileFormat.SaltSize).ToArray();
            kdfIterations = BinaryPrimitives.ReadUInt32LittleEndian(
                header.AsSpan(EncryptedFileFormat.KdfIterationsOffset));
        }

        return new FileHeaderInfo
        {
            FormatVersion = version,
            BlockSizeExponent = blockSizeExponent,
            AlgorithmId = algorithmId,
            KdfMethod = kdfMethod,
            Salt = salt,
            KdfIterations = kdfIterations,
        };
    }

    /// <inheritdoc />
    public Stream Create(string path, FileMode mode, CipheredFileStreamOptions? options = null)
        => Create(path, mode, FileAccess.ReadWrite, FileShare.None, options);

    /// <inheritdoc />
    public Stream Create(string path, FileMode mode, FileAccess access, CipheredFileStreamOptions? options = null)
        => Create(path, mode, access, FileShare.None, options);

    /// <inheritdoc />
    public Stream Create(string path, FileMode mode, FileAccess access, FileShare share,
        CipheredFileStreamOptions? options = null)
    {
        ThrowHelper.ThrowIfDisposed(_disposed, this);
        ThrowHelper.ThrowIfNullOrEmpty(path, nameof(path));

        options ??= new CipheredFileStreamOptions();

        // Determine KDF method from key provider type
        KdfMethod kdfMethod = _keyProvider is PasswordKeyProvider
            ? KdfMethod.Pbkdf2Sha256
            : KdfMethod.None;

        // Adjust FileAccess: Write alone is not sufficient because we need to read/write headers.
        if (access == FileAccess.Write)
            access = FileAccess.ReadWrite;

        // Handle Append: convert to OpenOrCreate with ReadWrite
        if (mode == FileMode.Append)
        {
            mode = FileMode.OpenOrCreate;
            access = FileAccess.ReadWrite;
        }

        // Determine FileStream buffering and options based on AccessPattern
        int fileStreamBufferSize;
        FileOptions fileOptions;
        int blockSizeExponent = (int)options.BlockSize;

        var cryptoFactory = new BlockCryptoFactory((byte)options.Algorithm);
        int ciphertextOverhead = cryptoFactory.GetCiphertextOverhead((byte)options.Algorithm);
        var layout = new BlockLayout(blockSizeExponent, ciphertextOverhead);

        if (options.AccessPattern == AccessPattern.Sequential)
        {
            // 1 MB buffer with SequentialScan hint for sequential access
            fileStreamBufferSize = 1024 * 1024;
            fileOptions = FileOptions.SequentialScan;
        }
        else
        {
            // Block-sized buffer for random access
            fileStreamBufferSize = layout.BlockSize;
            fileOptions = FileOptions.RandomAccess;
        }

        var fileStream = new FileStream(path, mode, access, share, fileStreamBufferSize, fileOptions);

        try
        {
            // Build KDF parameters for CipheredFileStream if using password-based key derivation
            byte[]? salt = null;
            uint iterations = 0;

            if (kdfMethod == KdfMethod.Pbkdf2Sha256 && _keyProvider is PasswordKeyProvider passwordProvider)
            {
                salt = passwordProvider.Salt;
                iterations = passwordProvider.Iterations;
            }

            return new Internal.CipheredFileStream(
                fileStream,
                _key!,
                mode,
                access,
                layout,
                cryptoFactory,
                (byte)options.Algorithm,
                kdfMethod,
                salt,
                iterations,
                options.AccessPattern,
                options.BufferSize,
                options.ConcurrencyLevel,
                path);
        }
        catch
        {
            fileStream.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            if (_key is not null)
            {
                Array.Clear(_key, 0, _key.Length);
                _key = null;
            }
            _disposed = true;
        }
    }
}
