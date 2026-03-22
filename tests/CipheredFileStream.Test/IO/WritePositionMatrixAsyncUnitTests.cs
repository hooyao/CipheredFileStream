using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Async write position matrix tests.
/// Systematic async writes at various positions with verification.
/// Uses RandomAccess pattern. All tests parameterized by block size.
/// </summary>
public class WritePositionMatrixAsyncUnitTests : CryptoTestBase
{
    private const int GcmOverhead = 28;

    private static CipheredFileStreamOptions MakeOptions(BlockSizeOption blockSize) => new()
    {
        BlockSize = blockSize,
        AccessPattern = AccessPattern.RandomAccess,
    };

    /// <summary>
    /// Helper: reads entire file content into a byte array asynchronously.
    /// </summary>
    private async Task<byte[]> ReadAllAsync(string path, int expectedSize, CipheredFileStreamOptions options)
    {
        var buffer = new byte[expectedSize];
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        int totalRead = 0;
        while (totalRead < expectedSize)
        {
            int read = await stream.ReadAsync(buffer, totalRead, expectedSize - totalRead);
            if (read == 0) break;
            totalRead += read;
        }
        return buffer.AsSpan(0, totalRead).ToArray();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_FirstByte(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wafirst_{blockSize}.enc");

        // Create file with 1000 zero bytes
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(new byte[1000], 0, 1000);
        }

        // Write 0xFF at position 0
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(0, SeekOrigin.Begin);
            await stream.WriteAsync(new byte[] { 0xFF }, 0, 1);
            await stream.FlushAsync();
        }

        var result = await ReadAllAsync(path, 1000, options);
        result[0].Should().Be(0xFF);
        result.Skip(1).Should().OnlyContain(b => b == 0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_FillBlock0(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wafillb0_{blockSize}.enc");
        int count = layout.Block0DataCapacity;

        var data = new byte[count];
        for (int i = 0; i < count; i++)
            data[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        var result = await ReadAllAsync(path, count, options);
        result.Should().Equal(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_SpillToBlock1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"waspill_{blockSize}.enc");
        int count = layout.Block0DataCapacity + 100;

        var data = new byte[count];
        for (int i = 0; i < count; i++)
            data[i] = (byte)(i % 239);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        var result = await ReadAllAsync(path, count, options);
        result.Should().Equal(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_LastByteOfBlock0(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"walastb0_{blockSize}.enc");
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;

        // Create file filled with zeros
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(new byte[fileSize], 0, fileSize);
        }

        // Write 1 byte at the last position of block 0
        int position = layout.Block0DataCapacity - 1;
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(position, SeekOrigin.Begin);
            await stream.WriteAsync(new byte[] { 0xAB }, 0, 1);
            await stream.FlushAsync();
        }

        var result = await ReadAllAsync(path, fileSize, options);
        result[position].Should().Be(0xAB);
        // Verify surrounding bytes are still zero
        if (position > 0) result[position - 1].Should().Be(0);
        result[position + 1].Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_CrossBlock0Block1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wacross01_{blockSize}.enc");
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;

        // Create file filled with zeros
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(new byte[fileSize], 0, fileSize);
        }

        // Write 100 bytes crossing the block 0/1 boundary
        int position = layout.Block0DataCapacity - 50;
        var writeData = new byte[100];
        for (int i = 0; i < 100; i++)
            writeData[i] = (byte)(0x80 + i);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(position, SeekOrigin.Begin);
            await stream.WriteAsync(writeData, 0, writeData.Length);
            await stream.FlushAsync();
        }

        var result = await ReadAllAsync(path, fileSize, options);

        // Bytes before the write should be zero
        result.Take(position).Should().OnlyContain(b => b == 0);
        // Written bytes should match
        result.Skip(position).Take(100).Should().Equal(writeData);
        // Bytes after the write should be zero
        result.Skip(position + 100).Should().OnlyContain(b => b == 0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_FirstByteOfBlock1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wafirstb1_{blockSize}.enc");
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;

        // Create file filled with zeros
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(new byte[fileSize], 0, fileSize);
        }

        // Write at the first position of block 1
        int position = layout.Block0DataCapacity;
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(position, SeekOrigin.Begin);
            await stream.WriteAsync(new byte[] { 0xCD }, 0, 1);
            await stream.FlushAsync();
        }

        var result = await ReadAllAsync(path, fileSize, options);
        result[position].Should().Be(0xCD);
        result[position - 1].Should().Be(0);
        if (position + 1 < fileSize)
            result[position + 1].Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_BeyondEOF(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wagap_{blockSize}.enc");

        // Create a 1000-byte file with pattern data
        var initialData = new byte[1000];
        for (int i = 0; i < 1000; i++)
            initialData[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(initialData, 0, initialData.Length);
        }

        // Write 10 bytes at position 2000 (beyond current EOF at 1000)
        var writeData = new byte[10];
        Array.Fill(writeData, (byte)0xEE);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(2000, SeekOrigin.Begin);
            await stream.WriteAsync(writeData, 0, writeData.Length);
            await stream.FlushAsync();
        }

        // Verify: file should now be 2010 bytes
        var result = await ReadAllAsync(path, 2010, options);
        result.Should().HaveCount(2010);

        // First 1000 bytes should be original data
        result.Take(1000).Should().Equal(initialData);
        // Gap (1000-1999) should be zeros
        result.Skip(1000).Take(1000).Should().OnlyContain(b => b == 0);
        // Written bytes at 2000-2009
        result.Skip(2000).Take(10).Should().OnlyContain(b => b == 0xEE);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_LargeChunked(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"walarge_{blockSize}.enc");
        int totalSize = 200 * 1024; // 200 KB
        const int chunkSize = 8192; // 8 KB chunks

        var data = new byte[totalSize];
        for (int i = 0; i < totalSize; i++)
            data[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            int offset = 0;
            while (offset < totalSize)
            {
                int toWrite = Math.Min(chunkSize, totalSize - offset);
                await stream.WriteAsync(data, offset, toWrite);
                offset += toWrite;
            }
            await stream.FlushAsync();
        }

        var result = await ReadAllAsync(path, totalSize, options);
        result.Should().HaveCount(totalSize);
        result.Should().Equal(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_ThenFlushAsync_ThenReadAsync(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wacycle_{blockSize}.enc");
        int size = layout.Block0DataCapacity + layout.BlockNDataCapacity + 500;

        var data = new byte[size];
        for (int i = 0; i < size; i++)
            data[i] = (byte)(i % 251);

        // Write, flush, close
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
            await stream.FlushAsync();
        }

        // Reopen and read back asynchronously
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(size);

            var result = new byte[size];
            int totalRead = 0;
            while (totalRead < size)
            {
                int r = await stream.ReadAsync(result, totalRead, size - totalRead);
                if (r == 0) break;
                totalRead += r;
            }

            totalRead.Should().Be(size);
            result.Should().Equal(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_OverwriteMiddle(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wamiddle_{blockSize}.enc");

        // Create 1000-byte file with pattern data
        var data = new byte[1000];
        for (int i = 0; i < 1000; i++)
            data[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        // Overwrite 100 bytes in the middle (positions 400-499)
        var overwrite = new byte[100];
        Array.Fill(overwrite, (byte)0xFF);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(400, SeekOrigin.Begin);
            await stream.WriteAsync(overwrite, 0, overwrite.Length);
            await stream.FlushAsync();
        }

        var result = await ReadAllAsync(path, 1000, options);

        // First 400 bytes unchanged
        result.Take(400).Should().Equal(data.Take(400));
        // Middle 100 bytes overwritten
        result.Skip(400).Take(100).Should().OnlyContain(b => b == 0xFF);
        // Last 500 bytes unchanged
        result.Skip(500).Take(500).Should().Equal(data.Skip(500).Take(500));
    }
}
