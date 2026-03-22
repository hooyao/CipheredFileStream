namespace CipheredFileStream.IO;

/// <summary>
/// Configuration options for creating encrypted file streams.
/// </summary>
public class CipheredFileStreamOptions
{
    /// <summary>
    /// Block size for new files. Ignored when opening existing files (read from header).
    /// Default: <see cref="BlockSizeOption.Block16K"/>.
    /// </summary>
    public BlockSizeOption BlockSize { get; set; } = BlockSizeOption.Block16K;

    /// <summary>
    /// Access pattern hint for IO optimization.
    /// Default: <see cref="AccessPattern.Sequential"/>.
    /// </summary>
    public AccessPattern AccessPattern { get; set; } = AccessPattern.Sequential;

    /// <summary>
    /// Buffer size in bytes for ring buffers (sequential mode).
    /// 0 means use internal default (1 MB).
    /// </summary>
    public int BufferSize { get; set; }

    /// <summary>
    /// Number of parallel crypto workers.
    /// 0 = default (2). 1 = disable parallelism.
    /// Capped to <see cref="Environment.ProcessorCount"/>.
    /// </summary>
    public int ConcurrencyLevel { get; set; }

    /// <summary>
    /// Encryption algorithm for new files. Ignored when opening existing files (auto-detected from header).
    /// Default: <see cref="EncryptionAlgorithm.AesGcm"/>.
    /// </summary>
    public EncryptionAlgorithm Algorithm { get; set; } = EncryptionAlgorithm.AesGcm;
}
