namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Static constants for the encrypted file format (v3).
/// </summary>
internal static class EncryptedFileFormat
{
    // --- File identification ---
    public const ushort MagicBytes = 0x4342;           // "BC" little-endian (bytes 0x42, 0x43)
    public const ushort FormatVersion = 0x0003;
    public const ushort MaxSupportedVersion = 0x0003;

    // --- Cleartext header (32 bytes, always fixed size) ---
    // [Magic 2B][Version 2B][BSE 1B][AlgId 1B][KdfMethod 1B][Reserved 1B][Salt 16B][Iterations 4B][Reserved 4B]
    public const int CleartextHeaderSize = 32;
    public const int BlockSizeExponentOffset = 4;
    public const int AlgorithmIdOffset = 5;
    public const int KdfMethodOffset = 6;
    public const int SaltOffset = 8;
    public const int SaltSize = 16;
    public const int KdfIterationsOffset = 24;

    // --- Block structure ---
    public const int CiphertextLengthPrefixSize = 4;   // uint32 LE

    // --- Protobuf header within block 0 payload ---
    public const int HeaderLengthPrefixSize = 2;        // uint16 LE
    public const int ProtobufHeaderMaxSize = 85;        // reserved region

    // --- Integrity ---
    public const int IntegrityHashSize = 32;

    // --- AAD ---
    public const int AadSize = 8;                       // block index as int64 LE

    // --- Key ---
    public const int KeySize = 32;                      // AES-256

    // --- Header schema ---
    public const int HeaderSchemaVersion = 1;

    // --- Block size bounds ---
    public const int MinBlockSizeExponent = 12;         // 4 KB
    public const int MaxBlockSizeExponent = 17;         // 128 KB
    public const int DefaultBlockSizeExponent = 14;     // 16 KB
}
