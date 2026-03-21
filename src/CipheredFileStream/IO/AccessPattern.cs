namespace CipheredFileStream.IO;

/// <summary>
/// Hint for how the stream will be accessed, enabling IO optimizations.
/// </summary>
public enum AccessPattern
{
    /// <summary>
    /// Sequential access. Enables ring buffers with bulk IO and parallel encrypt/decrypt.
    /// Automatically falls back to random access on non-sequential operations.
    /// </summary>
    Sequential,

    /// <summary>
    /// Random access. Uses a single-block cache with minimal memory overhead.
    /// </summary>
    RandomAccess,
}
