using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Async mirrors of <see cref="ReadPositionMatrixUnitTests"/>.
/// Systematic async reads from various (position, count) combinations across block boundaries.
/// All tests parameterized by block size.
/// </summary>
public class ReadPositionMatrixAsyncUnitTests : CryptoTestBase
{
    private const int GcmOverhead = 28;

    /// <summary>
    /// Creates a test file filled with pattern data (byte = i % 251) spanning 3+ blocks.
    /// </summary>
    private async Task<(string path, byte[] data, BlockLayout layout)> CreateTestFileAsync(
        string path, int size, BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var data = new byte[size];
        for (int i = 0; i < size; i++)
            data[i] = (byte)(i % 251);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        return (path, data, layout);
    }

    /// <summary>
    /// Creates a pattern file spanning 3+ blocks for the given block size.
    /// </summary>
    private async Task<(string path, byte[] data, BlockLayout layout)> CreatePatternFileAsync(
        BlockSizeOption blockSize, string suffix)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        int dataSize = layout.Block0DataCapacity + layout.BlockNDataCapacity * 2 + 500;
        var path = GetTestFilePath($"readasync_{suffix}_{blockSize}.enc");
        return await CreateTestFileAsync(path, dataSize, blockSize);
    }

    private static async Task<byte[]> ReadAtPositionAsync(Stream stream, long position, int count)
    {
        stream.Seek(position, SeekOrigin.Begin);
        var buffer = new byte[count];
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = await stream.ReadAsync(buffer, totalRead, count - totalRead);
            if (read == 0) break;
            totalRead += read;
        }
        return buffer.AsSpan(0, totalRead).ToArray();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_FirstByte(BlockSizeOption blockSize)
    {
        var (path, data, _) = await CreatePatternFileAsync(blockSize, "firstbyte");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, 0, 1);

        result.Should().HaveCount(1);
        result[0].Should().Be(data[0]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_First100Bytes(BlockSizeOption blockSize)
    {
        var (path, data, _) = await CreatePatternFileAsync(blockSize, "first100");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, 0, 100);

        result.Should().HaveCount(100);
        result.Should().Equal(data.AsSpan(0, 100).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_WithinBlock0_Middle(BlockSizeOption blockSize)
    {
        var (path, data, _) = await CreatePatternFileAsync(blockSize, "mid0");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, 500, 200);

        result.Should().HaveCount(200);
        result.Should().Equal(data.AsSpan(500, 200).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_LastByteOfBlock0(BlockSizeOption blockSize)
    {
        var (path, data, layout) = await CreatePatternFileAsync(blockSize, "lastb0");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity - 1;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, position, 1);

        result.Should().HaveCount(1);
        result[0].Should().Be(data[position]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_FirstByteOfBlock1(BlockSizeOption blockSize)
    {
        var (path, data, layout) = await CreatePatternFileAsync(blockSize, "firstb1");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, position, 1);

        result.Should().HaveCount(1);
        result[0].Should().Be(data[position]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_CrossingBlock0Block1(BlockSizeOption blockSize)
    {
        var (path, data, layout) = await CreatePatternFileAsync(blockSize, "cross01");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity - 50;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, position, 100);

        result.Should().HaveCount(100);
        result.Should().Equal(data.AsSpan(position, 100).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_EntireBlock1(BlockSizeOption blockSize)
    {
        var (path, data, layout) = await CreatePatternFileAsync(blockSize, "block1");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity;
        int count = layout.BlockNDataCapacity;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, position, count);

        result.Should().HaveCount(count);
        result.Should().Equal(data.AsSpan(position, count).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_CrossingBlock1Block2(BlockSizeOption blockSize)
    {
        var (path, data, layout) = await CreatePatternFileAsync(blockSize, "cross12");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity + layout.BlockNDataCapacity - 50;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, position, 100);

        result.Should().HaveCount(100);
        result.Should().Equal(data.AsSpan(position, 100).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_FirstByteOfBlock2(BlockSizeOption blockSize)
    {
        var (path, data, layout) = await CreatePatternFileAsync(blockSize, "firstb2");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        int position = layout.Block0DataCapacity + layout.BlockNDataCapacity;

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var result = await ReadAtPositionAsync(stream, position, 1);

        result.Should().HaveCount(1);
        result[0].Should().Be(data[position]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_LastBytesOfFile(BlockSizeOption blockSize)
    {
        var (path, data, _) = await CreatePatternFileAsync(blockSize, "lastbytes");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Seek(-10, SeekOrigin.End);

        var buffer = new byte[10];
        int totalRead = 0;
        while (totalRead < 10)
        {
            int read = await stream.ReadAsync(buffer, totalRead, 10 - totalRead);
            if (read == 0) break;
            totalRead += read;
        }

        totalRead.Should().Be(10);
        buffer.Should().Equal(data.AsSpan(data.Length - 10, 10).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_RequestMoreThanAvailable(BlockSizeOption blockSize)
    {
        var (path, data, _) = await CreatePatternFileAsync(blockSize, "morethan");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        // Seek to 50 bytes before end, request 10000
        int nearEnd = data.Length - 50;
        var result = await ReadAtPositionAsync(stream, nearEnd, 10000);

        result.Should().HaveCount(50);
        result.Should().Equal(data.AsSpan(nearEnd, 50).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_EmptyFile_ReturnsZero(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"readasync_empty_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            // Write nothing — empty file
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            var buf = new byte[100];
            int read = await stream.ReadAsync(buf, 0, buf.Length);
            read.Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_SingleByteFile(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"readasync_single_{blockSize}.enc");
        var (_, data, _) = await CreateTestFileAsync(path, 1, blockSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var buf = new byte[1];
        int read = await stream.ReadAsync(buf, 0, 1);

        read.Should().Be(1);
        buf[0].Should().Be(data[0]);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_InChunks_64KB(BlockSizeOption blockSize)
    {
        var (path, data, layout) = await CreatePatternFileAsync(blockSize, "chunks64k");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var result = new byte[data.Length];
        int totalRead = 0;
        const int chunkSize = 65536;
        while (totalRead < data.Length)
        {
            int toRead = Math.Min(chunkSize, data.Length - totalRead);
            int r = await stream.ReadAsync(result, totalRead, toRead);
            if (r == 0) break;
            totalRead += r;
        }

        totalRead.Should().Be(data.Length);
        result.Should().Equal(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_AfterSeek_Begin(BlockSizeOption blockSize)
    {
        var (path, data, layout) = await CreatePatternFileAsync(blockSize, "seekbegin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        // Read some bytes first to advance position
        var discard = new byte[100];
        await stream.ReadAsync(discard, 0, discard.Length);

        // Seek back to a specific position using Begin
        int seekPos = layout.Block0DataCapacity + 200;
        stream.Seek(seekPos, SeekOrigin.Begin);

        var result = await ReadAtPositionAsync(stream, seekPos, 150);

        result.Should().HaveCount(150);
        result.Should().Equal(data.AsSpan(seekPos, 150).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_AfterSeek_End(BlockSizeOption blockSize)
    {
        var (path, data, _) = await CreatePatternFileAsync(blockSize, "seekend");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        // Seek to 200 bytes before the end
        stream.Seek(-200, SeekOrigin.End);

        var buffer = new byte[200];
        int totalRead = 0;
        while (totalRead < 200)
        {
            int read = await stream.ReadAsync(buffer, totalRead, 200 - totalRead);
            if (read == 0) break;
            totalRead += read;
        }

        totalRead.Should().Be(200);
        buffer.Should().Equal(data.AsSpan(data.Length - 200, 200).ToArray());
    }
}
