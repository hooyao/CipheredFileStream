namespace CipheredFileStream.IO;

/// <summary>
/// Block size for new encrypted files. Values are power-of-2 exponents.
/// Ignored when opening existing files (block size is read from the header).
/// </summary>
public enum BlockSizeOption
{
    /// <summary>4 KB blocks (exponent 12).</summary>
    Block4K = 12,

    /// <summary>8 KB blocks (exponent 13).</summary>
    Block8K = 13,

    /// <summary>16 KB blocks (exponent 14). Default.</summary>
    Block16K = 14,

    /// <summary>32 KB blocks (exponent 15).</summary>
    Block32K = 15,

    /// <summary>64 KB blocks (exponent 16).</summary>
    Block64K = 16,

    /// <summary>128 KB blocks (exponent 17).</summary>
    Block128K = 17,
}
