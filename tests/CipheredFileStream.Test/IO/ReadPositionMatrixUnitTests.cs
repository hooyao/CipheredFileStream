using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Systematic reads from various (position, count) combinations across block boundaries.
/// All tests parameterized by block size.
/// </summary>
public class ReadPositionMatrixUnitTests : CryptoTestBase
{
    private const int GcmOverhead = 28;

    /// <summary>
    /// Creates a test file filled with pattern data (byte = i % 251) spanning 3+ blocks,
    /// then returns the expected data array and the file path.
    /// </summary>
    private (string path, byte[] data, BlockLayout layout) CreatePatternFile(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        // Ensure data spans at least 3 blocks
        int dataSize = layout.Block0DataCapacity + layout.BlockNDataCapacity * 2 + 500;
        var data = new byte[dataSize];
        for (int i = 0; i < dataSize; i++)
            data[i] = (byte)(i % 251);

        var path = GetTestFilePath($"readmatrix_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        return (path, data, layout);
    }

    private static byte[] ReadAtPosition(Stream stream, long position, int count)
    {
        stream.Seek(position, SeekOrigin.Begin);
        var buffer = new byte[count];
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = stream.Read(buffer, totalRead, count - totalRead);
            if (read == 0) break;
            totalRead += read;
        }
        return buffer.AsSpan(0, totalRead).ToArray();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_FirstByte(BlockSizeOption blockSize)
    {
        var (path, data, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, 0, 1);

        result.Should().HaveCount(1);
        result[0].Should().Be(data[0]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_First100Bytes(BlockSizeOption blockSize)
    {
        var (path, data, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, 0, 100);

        result.Should().HaveCount(100);
        result.Should().Equal(data.AsSpan(0, 100).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_LastByteOfBlock0(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity - 1;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, 1);

        result.Should().HaveCount(1);
        result[0].Should().Be(data[position]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_FirstByteOfBlock1(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, 1);

        result.Should().HaveCount(1);
        result[0].Should().Be(data[position]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_CrossingBlock0Block1(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity - 50;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, 100);

        result.Should().HaveCount(100);
        result.Should().Equal(data.AsSpan(position, 100).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_EntireBlock1(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity;
        int count = layout.BlockNDataCapacity;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, count);

        result.Should().HaveCount(count);
        result.Should().Equal(data.AsSpan(position, count).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_CrossingBlock1Block2(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity + layout.BlockNDataCapacity - 50;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, 100);

        result.Should().HaveCount(100);
        result.Should().Equal(data.AsSpan(position, 100).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_FirstByteOfBlock2(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity + layout.BlockNDataCapacity;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, 1);

        result.Should().HaveCount(1);
        result[0].Should().Be(data[position]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_LastBytesOfFile(BlockSizeOption blockSize)
    {
        var (path, data, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Seek(-10, SeekOrigin.End);
        var buffer = new byte[10];
        int totalRead = 0;
        while (totalRead < 10)
        {
            int read = stream.Read(buffer, totalRead, 10 - totalRead);
            if (read == 0) break;
            totalRead += read;
        }

        totalRead.Should().Be(10);
        buffer.Should().Equal(data.AsSpan(data.Length - 10, 10).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_RequestMoreThanAvailable(BlockSizeOption blockSize)
    {
        var (path, data, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        // Seek to 20 bytes before end
        int nearEnd = data.Length - 20;
        var result = ReadAtPosition(stream, nearEnd, 1000);

        // Should only get the remaining 20 bytes
        result.Should().HaveCount(20);
        result.Should().Equal(data.AsSpan(nearEnd, 20).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_Position0_ExactlyBlock0Capacity(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int count = layout.Block0DataCapacity;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, 0, count);

        result.Should().HaveCount(count);
        result.Should().Equal(data.AsSpan(0, count).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_Position0_SpillsToBlock1(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int count = layout.Block0DataCapacity + 100;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, 0, count);

        result.Should().HaveCount(count);
        result.Should().Equal(data.AsSpan(0, count).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_Position0_Across3Blocks(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int count = layout.Block0DataCapacity + layout.BlockNDataCapacity + 100;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, 0, count);

        result.Should().HaveCount(count);
        result.Should().Equal(data.AsSpan(0, count).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_Position0_EntireFile(BlockSizeOption blockSize)
    {
        var (path, data, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, 0, data.Length);

        result.Should().HaveCount(data.Length);
        result.Should().Equal(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_FromEndOfBlock0_IntoBlock1(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity - 50;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, 100);

        result.Should().HaveCount(100);
        result.Should().Equal(data.AsSpan(position, 100).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_Block1AndBeyond_8KB(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity;
        int count = Math.Min(8192, data.Length - position);

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, count);

        result.Should().HaveCount(count);
        result.Should().Equal(data.AsSpan(position, count).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_PastEOF_ReturnsPartial(BlockSizeOption blockSize)
    {
        var (path, data, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = data.Length - 50;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, position, 100);

        result.Should().HaveCount(50);
        result.Should().Equal(data.AsSpan(position, 50).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_AtEOF_ReturnsZero(BlockSizeOption blockSize)
    {
        var (path, data, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, data.Length, 100);

        result.Should().HaveCount(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_BeyondEOF_ReturnsZero(BlockSizeOption blockSize)
    {
        var (path, data, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = ReadAtPosition(stream, data.Length + 100, 100);

        result.Should().HaveCount(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_ZeroLength_ReturnsZero(BlockSizeOption blockSize)
    {
        var (path, _, _) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var buffer = new byte[10];
        int read = stream.Read(buffer, 0, 0);

        read.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_VariousPositionsAndLengths(BlockSizeOption blockSize)
    {
        var (path, data, layout) = CreatePatternFile(blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var testCases = new (int position, int length)[]
        {
            (0, 1),
            (50, 200),
            (layout.Block0DataCapacity - 10, 20),
            (layout.Block0DataCapacity + layout.BlockNDataCapacity - 10, 20),
            (data.Length - 100, 100),
        };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        foreach (var (position, length) in testCases)
        {
            var result = ReadAtPosition(stream, position, length);

            result.Should().HaveCount(length);
            result.Should().Equal(data.AsSpan(position, length).ToArray(),
                because: $"reading {length} bytes from position {position} should match source data");
        }
    }
}
