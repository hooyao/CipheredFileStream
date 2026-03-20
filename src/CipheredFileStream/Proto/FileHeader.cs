using Google.Protobuf;
using Google.Protobuf.Reflection;
using static Google.Protobuf.WireFormat;

namespace CipheredFileStream.Proto;

public enum ChunkSize
{
    Size4K = 0,
    Size8K = 1,
    Size16K = 2,
    Size32K = 3,
    Size64K = 4,
    Size128K = 5
}

public enum KeyDerivation
{
    None = 0,
    Pbkdf2 = 1
}

public sealed class KeyInfo : IMessage<KeyInfo>
{
    private static readonly MessageParser<KeyInfo> _parser = new(() => new KeyInfo());
    public static MessageParser<KeyInfo> Parser => _parser;

    public KeyDerivation Method { get; set; }
    public ByteString Salt { get; set; } = ByteString.Empty;
    public uint Iterations { get; set; }

    public void WriteTo(CodedOutputStream output)
    {
        if (Method != KeyDerivation.None)
        {
            output.WriteTag(1, WireType.Varint);
            output.WriteEnum((int)Method);
        }
        if (Salt.Length > 0)
        {
            output.WriteTag(2, WireType.LengthDelimited);
            output.WriteBytes(Salt);
        }
        if (Iterations != 0)
        {
            output.WriteTag(3, WireType.Varint);
            output.WriteUInt32(Iterations);
        }
    }

    public int CalculateSize()
    {
        int size = 0;
        if (Method != KeyDerivation.None)
            size += 1 + CodedOutputStream.ComputeEnumSize((int)Method);
        if (Salt.Length > 0)
            size += 1 + CodedOutputStream.ComputeBytesSize(Salt);
        if (Iterations != 0)
            size += 1 + CodedOutputStream.ComputeUInt32Size(Iterations);
        return size;
    }

    public void MergeFrom(CodedInputStream input)
    {
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            switch (tag >> 3)
            {
                case 1: Method = (KeyDerivation)input.ReadEnum(); break;
                case 2: Salt = input.ReadBytes(); break;
                case 3: Iterations = input.ReadUInt32(); break;
                default: input.SkipLastField(); break;
            }
        }
    }

    public MessageDescriptor Descriptor => null!;
    public KeyInfo Clone() => new() { Method = Method, Salt = Salt, Iterations = Iterations };
    public bool Equals(KeyInfo? other) => other is not null && Method == other.Method && Salt == other.Salt && Iterations == other.Iterations;
    public override bool Equals(object? obj) => Equals(obj as KeyInfo);
    public override int GetHashCode() => HashCode.Combine(Method, Salt, Iterations);
    public void MergeFrom(KeyInfo message) { Method = message.Method; Salt = message.Salt; Iterations = message.Iterations; }
    public override string ToString() => $"KeyInfo {{ Method = {Method}, Salt = {Salt}, Iterations = {Iterations} }}";
}

public sealed class FileHeader : IMessage<FileHeader>
{
    private static readonly MessageParser<FileHeader> _parser = new(() => new FileHeader());
    public static MessageParser<FileHeader> Parser => _parser;

    public ChunkSize ChunkSize { get; set; }
    public ulong PlaintextLength { get; set; }
    public uint ChunkCount { get; set; }
    public ByteString MasterNonce { get; set; } = ByteString.Empty;
    public KeyInfo? KeyInfo { get; set; }
    public ByteString TotalChecksum { get; set; } = ByteString.Empty;

    public void WriteTo(CodedOutputStream output)
    {
        if (ChunkSize != ChunkSize.Size4K)
        {
            output.WriteTag(1, WireType.Varint);
            output.WriteEnum((int)ChunkSize);
        }
        if (PlaintextLength != 0)
        {
            output.WriteTag(2, WireType.Varint);
            output.WriteUInt64(PlaintextLength);
        }
        if (ChunkCount != 0)
        {
            output.WriteTag(3, WireType.Varint);
            output.WriteUInt32(ChunkCount);
        }
        if (MasterNonce.Length > 0)
        {
            output.WriteTag(4, WireType.LengthDelimited);
            output.WriteBytes(MasterNonce);
        }
        if (KeyInfo is not null)
        {
            output.WriteTag(5, WireType.LengthDelimited);
            output.WriteMessage(KeyInfo);
        }
        if (TotalChecksum.Length > 0)
        {
            output.WriteTag(6, WireType.LengthDelimited);
            output.WriteBytes(TotalChecksum);
        }
    }

    public int CalculateSize()
    {
        int size = 0;
        if (ChunkSize != ChunkSize.Size4K)
            size += 1 + CodedOutputStream.ComputeEnumSize((int)ChunkSize);
        if (PlaintextLength != 0)
            size += 1 + CodedOutputStream.ComputeUInt64Size(PlaintextLength);
        if (ChunkCount != 0)
            size += 1 + CodedOutputStream.ComputeUInt32Size(ChunkCount);
        if (MasterNonce.Length > 0)
            size += 1 + CodedOutputStream.ComputeBytesSize(MasterNonce);
        if (KeyInfo is not null)
            size += 1 + CodedOutputStream.ComputeMessageSize(KeyInfo);
        if (TotalChecksum.Length > 0)
            size += 1 + CodedOutputStream.ComputeBytesSize(TotalChecksum);
        return size;
    }

    public void MergeFrom(CodedInputStream input)
    {
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            switch (tag >> 3)
            {
                case 1: ChunkSize = (Proto.ChunkSize)input.ReadEnum(); break;
                case 2: PlaintextLength = input.ReadUInt64(); break;
                case 3: ChunkCount = input.ReadUInt32(); break;
                case 4: MasterNonce = input.ReadBytes(); break;
                case 5:
                    KeyInfo = new KeyInfo();
                    input.ReadMessage(KeyInfo);
                    break;
                case 6: TotalChecksum = input.ReadBytes(); break;
                default: input.SkipLastField(); break;
            }
        }
    }

    public MessageDescriptor Descriptor => null!;
    public FileHeader Clone() => new()
    {
        ChunkSize = ChunkSize,
        PlaintextLength = PlaintextLength,
        ChunkCount = ChunkCount,
        MasterNonce = MasterNonce,
        KeyInfo = KeyInfo?.Clone(),
        TotalChecksum = TotalChecksum
    };
    public bool Equals(FileHeader? other) => other is not null
        && ChunkSize == other.ChunkSize
        && PlaintextLength == other.PlaintextLength
        && ChunkCount == other.ChunkCount
        && MasterNonce == other.MasterNonce
        && Equals(KeyInfo, other.KeyInfo)
        && TotalChecksum == other.TotalChecksum;
    public override bool Equals(object? obj) => Equals(obj as FileHeader);
    public override int GetHashCode() => HashCode.Combine(ChunkSize, PlaintextLength, ChunkCount, MasterNonce, KeyInfo, TotalChecksum);
    public void MergeFrom(FileHeader message)
    {
        ChunkSize = message.ChunkSize;
        PlaintextLength = message.PlaintextLength;
        ChunkCount = message.ChunkCount;
        MasterNonce = message.MasterNonce;
        KeyInfo = message.KeyInfo?.Clone();
        TotalChecksum = message.TotalChecksum;
    }
    public override string ToString() => $"FileHeader {{ ChunkSize = {ChunkSize}, PlaintextLength = {PlaintextLength}, ChunkCount = {ChunkCount} }}";
}
