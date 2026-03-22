using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class AsyncOperationsUnitTests : CryptoTestBase
{
    /// <summary>
    /// Creates a test file filled with pattern data where each byte = i % 251.
    /// </summary>
    private void CreateTestFile(string path, int size, BlockSizeOption blockSize)
    {
        var data = new byte[size];
        for (int i = 0; i < size; i++)
            data[i] = (byte)(i % 251);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Create, options);
        stream.Write(data, 0, data.Length);
    }

    /// <summary>
    /// Builds the expected pattern data for verification.
    /// </summary>
    private static byte[] ExpectedPattern(int offset, int length)
    {
        var data = new byte[length];
        for (int i = 0; i < length; i++)
            data[i] = (byte)((offset + i) % 251);
        return data;
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_EmptyFile_ReturnsZero(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"aempty_{blockSize}.enc");
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
    public async Task ReadAsync_SingleByte_AtPosition0(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"asingle_{blockSize}.enc");
        CreateTestFile(path, 1, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var buf = new byte[1];
        int read = await stream.ReadAsync(buf, 0, 1);
        read.Should().Be(1);
        buf[0].Should().Be(0); // 0 % 251 == 0
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_WithinBlock0(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity;
        var path = GetTestFilePath($"awithin0_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Seek(50, SeekOrigin.Begin);

        var buf = new byte[100];
        int totalRead = 0;
        while (totalRead < 100)
        {
            int r = await stream.ReadAsync(buf, totalRead, 100 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(100);
        buf.Should().BeEquivalentTo(ExpectedPattern(50, 100));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_ExactlyBlock0Capacity(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int cap = layout.Block0DataCapacity;
        var path = GetTestFilePath($"aexact0_{blockSize}.enc");
        CreateTestFile(path, cap, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var buf = new byte[cap];
        int totalRead = 0;
        while (totalRead < cap)
        {
            int r = await stream.ReadAsync(buf, totalRead, cap - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(cap);
        buf.Should().BeEquivalentTo(ExpectedPattern(0, cap));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_CrossingBlock0ToBlock1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;
        var path = GetTestFilePath($"across01_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        int readStart = layout.Block0DataCapacity - 50;
        stream.Seek(readStart, SeekOrigin.Begin);

        var buf = new byte[200];
        int totalRead = 0;
        while (totalRead < 200)
        {
            int r = await stream.ReadAsync(buf, totalRead, 200 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(200);
        buf.Should().BeEquivalentTo(ExpectedPattern(readStart, 200));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_EntireBlock1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;
        var path = GetTestFilePath($"ablock1_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        int block1Start = layout.Block0DataCapacity;
        stream.Seek(block1Start, SeekOrigin.Begin);

        var buf = new byte[layout.BlockNDataCapacity];
        int totalRead = 0;
        while (totalRead < buf.Length)
        {
            int r = await stream.ReadAsync(buf, totalRead, buf.Length - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(layout.BlockNDataCapacity);
        buf.Should().BeEquivalentTo(ExpectedPattern(block1Start, layout.BlockNDataCapacity));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_CrossingBlock1ToBlock2(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + 2 * layout.BlockNDataCapacity;
        var path = GetTestFilePath($"across12_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        int readStart = layout.Block0DataCapacity + layout.BlockNDataCapacity - 50;
        stream.Seek(readStart, SeekOrigin.Begin);

        var buf = new byte[200];
        int totalRead = 0;
        while (totalRead < 200)
        {
            int r = await stream.ReadAsync(buf, totalRead, 200 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(200);
        buf.Should().BeEquivalentTo(ExpectedPattern(readStart, 200));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_EntireFile_InChunks(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + 3 * layout.BlockNDataCapacity;
        var path = GetTestFilePath($"achunks_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var result = new byte[fileSize];
        int totalRead = 0;
        const int chunkSize = 65536;
        while (totalRead < fileSize)
        {
            int toRead = Math.Min(chunkSize, fileSize - totalRead);
            int r = await stream.ReadAsync(result, totalRead, toRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(fileSize);
        result.Should().BeEquivalentTo(ExpectedPattern(0, fileSize));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_BeyondEOF_ReturnsPartial(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"aeof_{blockSize}.enc");
        CreateTestFile(path, 100, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        stream.Seek(80, SeekOrigin.Begin);
        var buf = new byte[100];
        int totalRead = 0;
        while (totalRead < 100)
        {
            int r = await stream.ReadAsync(buf, totalRead, 100 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(20);
        buf.AsSpan(0, 20).ToArray().Should().BeEquivalentTo(ExpectedPattern(80, 20));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_SingleByte_Verify(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"aw1_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            var data = new byte[] { 0xAB };
            await stream.WriteAsync(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1);
            var buf = new byte[1];
            int read = await stream.ReadAsync(buf, 0, 1);
            read.Should().Be(1);
            buf[0].Should().Be(0xAB);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_FillBlock0_Verify(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int cap = layout.Block0DataCapacity;
        var path = GetTestFilePath($"afill0_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, cap);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(cap);
            var buf = new byte[cap];
            int totalRead = 0;
            while (totalRead < cap)
            {
                int r = await stream.ReadAsync(buf, totalRead, cap - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(cap);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_CrossBlock0ToBlock1_Verify(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int size = layout.Block0DataCapacity + 100;
        var path = GetTestFilePath($"awcross01_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, size);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(size);
            var buf = new byte[size];
            int totalRead = 0;
            while (totalRead < size)
            {
                int r = await stream.ReadAsync(buf, totalRead, size - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(size);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_MultipleBlocks_Verify(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int size = layout.Block0DataCapacity + 3 * layout.BlockNDataCapacity + 500;
        var path = GetTestFilePath($"awmulti_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, size);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(size);
            var buf = new byte[size];
            int totalRead = 0;
            while (totalRead < size)
            {
                int r = await stream.ReadAsync(buf, totalRead, size - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(size);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_ThenFlushAsync(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"aflush_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 5000);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
            await stream.FlushAsync();
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(5000);
            var buf = new byte[5000];
            int totalRead = 0;
            while (totalRead < 5000)
            {
                int r = await stream.ReadAsync(buf, totalRead, 5000 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(5000);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_ReadAsync_Interleaved(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"ainterleaved_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 1000);
        using var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options);

        // Write 1000 bytes
        await stream.WriteAsync(data, 0, data.Length);
        await stream.FlushAsync();

        // Seek back to beginning
        stream.Seek(0, SeekOrigin.Begin);

        // Read everything back
        var buf = new byte[1000];
        int totalRead = 0;
        while (totalRead < 1000)
        {
            int r = await stream.ReadAsync(buf, totalRead, 1000 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(1000);
        buf.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_WithOffset(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"aroffset_{blockSize}.enc");
        CreateTestFile(path, 1024, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var buf = new byte[200];
        int totalRead = 0;
        while (totalRead < 100)
        {
            int r = await stream.ReadAsync(buf, 50 + totalRead, 100 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(100);
        buf.AsSpan(50, 100).ToArray().Should().BeEquivalentTo(ExpectedPattern(0, 100));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_Memory(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"armemory_{blockSize}.enc");
        CreateTestFile(path, 1024, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var buf = new byte[256];
        int totalRead = 0;
        while (totalRead < 256)
        {
            int r = await stream.ReadAsync(buf.AsMemory(totalRead));
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(256);
        buf.Should().BeEquivalentTo(ExpectedPattern(0, 256));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_ZeroCount_ReturnsZero(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"arzero_{blockSize}.enc");
        CreateTestFile(path, 100, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var buf = new byte[100];
        int read = await stream.ReadAsync(buf, 0, 0);
        read.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task ReadAsync_CancellationRequested_Throws(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"arcancel_{blockSize}.enc");
        CreateTestFile(path, 1024, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var cts = new CancellationTokenSource();
        cts.Cancel();

        var buf = new byte[100];
        Func<Task> act = async () => await stream.ReadExactlyAsync(buf.AsMemory(0, 100), cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_WithOffset(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"awoffset_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var source = new byte[200];
        for (int i = 0; i < 200; i++)
            source[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(source, 50, 100);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(100);
            var buf = new byte[100];
            int totalRead = 0;
            while (totalRead < 100)
            {
                int r = await stream.ReadAsync(buf, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(100);
            buf.Should().BeEquivalentTo(source.AsSpan(50, 100).ToArray());
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_Memory(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"awmemory_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 512);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data.AsMemory());
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(512);
            var buf = new byte[512];
            int totalRead = 0;
            while (totalRead < 512)
            {
                int r = await stream.ReadAsync(buf, totalRead, 512 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(512);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_ZeroCount_NoChange(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"awzero_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            var buf = new byte[100];
            await stream.WriteAsync(buf, 0, 0);
            stream.Length.Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_CancellationRequested_Throws(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"awcancel_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Create, options);

        var cts = new CancellationTokenSource();
        cts.Cancel();

        var data = new byte[100];
        Func<Task> act = async () => await stream.WriteAsync(data.AsMemory(0, 100), cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_AtPosition_Overwrites(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"awoverwrite_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        CreateTestFile(path, 1024, blockSize);

        var overwrite = new byte[100];
        for (int i = 0; i < 100; i++)
            overwrite[i] = 0xAA;

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(200, SeekOrigin.Begin);
            await stream.WriteAsync(overwrite, 0, overwrite.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1024);

            // Check data before overwrite region
            var before = new byte[200];
            int totalRead = 0;
            while (totalRead < 200)
            {
                int r = await stream.ReadAsync(before, totalRead, 200 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            before.Should().BeEquivalentTo(ExpectedPattern(0, 200));

            // Check overwritten region
            var mid = new byte[100];
            totalRead = 0;
            while (totalRead < 100)
            {
                int r = await stream.ReadAsync(mid, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            mid.Should().OnlyContain(b => b == 0xAA);

            // Check data after overwrite region
            var after = new byte[724];
            totalRead = 0;
            while (totalRead < 724)
            {
                int r = await stream.ReadAsync(after, totalRead, 724 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(724);
            after.Should().BeEquivalentTo(ExpectedPattern(300, 724));
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_CrossingBlockBoundary_Overwrites(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;
        var path = GetTestFilePath($"awcrossoverwrite_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        CreateTestFile(path, fileSize, blockSize);

        int writeStart = layout.Block0DataCapacity - 50;
        var overwrite = new byte[100];
        for (int i = 0; i < 100; i++)
            overwrite[i] = 0xBB;

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(writeStart, SeekOrigin.Begin);
            await stream.WriteAsync(overwrite, 0, overwrite.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(fileSize);

            stream.Seek(0, SeekOrigin.Begin);
            var before = new byte[writeStart];
            int totalRead = 0;
            while (totalRead < writeStart)
            {
                int r = await stream.ReadAsync(before, totalRead, writeStart - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            before.Should().BeEquivalentTo(ExpectedPattern(0, writeStart));

            var mid = new byte[100];
            totalRead = 0;
            while (totalRead < 100)
            {
                int r = await stream.ReadAsync(mid, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            mid.Should().OnlyContain(b => b == 0xBB);

            int afterStart = writeStart + 100;
            int afterLen = fileSize - afterStart;
            var after = new byte[afterLen];
            totalRead = 0;
            while (totalRead < afterLen)
            {
                int r = await stream.ReadAsync(after, totalRead, afterLen - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(afterLen);
            after.Should().BeEquivalentTo(ExpectedPattern(afterStart, afterLen));
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task WriteAsync_BeyondEOF_ExtendsWithZeros(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"awbeyondeof_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        CreateTestFile(path, 1000, blockSize);

        var extra = new byte[100];
        for (int i = 0; i < 100; i++)
            extra[i] = 0xCC;

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(2000, SeekOrigin.Begin);
            await stream.WriteAsync(extra, 0, extra.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(2100);

            var orig = new byte[1000];
            int totalRead = 0;
            while (totalRead < 1000)
            {
                int r = await stream.ReadAsync(orig, totalRead, 1000 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            orig.Should().BeEquivalentTo(ExpectedPattern(0, 1000));

            var gap = new byte[1000];
            totalRead = 0;
            while (totalRead < 1000)
            {
                int r = await stream.ReadAsync(gap, totalRead, 1000 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(1000);
            gap.Should().OnlyContain(b => b == 0);

            var written = new byte[100];
            totalRead = 0;
            while (totalRead < 100)
            {
                int r = await stream.ReadAsync(written, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(100);
            written.Should().OnlyContain(b => b == 0xCC);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task FlushAsync_PersistsUnflushedData(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"aflushpersist_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 500);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
            // No explicit flush — dispose should handle it
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(500);
            var buf = new byte[500];
            int totalRead = 0;
            while (totalRead < 500)
            {
                int r = await stream.ReadAsync(buf, totalRead, 500 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(500);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task FlushAsync_MultipleFlushes_DataConsistent(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"amultiflush_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data1 = ExpectedPattern(0, 500);
        var data2 = ExpectedPattern(500, 500);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data1, 0, data1.Length);
            await stream.FlushAsync();

            await stream.WriteAsync(data2, 0, data2.Length);
            await stream.FlushAsync();
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1000);
            var buf = new byte[1000];
            int totalRead = 0;
            while (totalRead < 1000)
            {
                int r = await stream.ReadAsync(buf, totalRead, 1000 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(1000);
            buf.Should().BeEquivalentTo(ExpectedPattern(0, 1000));
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task FlushAsync_WithCancellation_CanBeCancelled(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"aflushcancel_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Create, options);

        var cts = new CancellationTokenSource();
        cts.Cancel();

        Func<Task> act = () => stream.FlushAsync(cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task FlushAsync_AfterSeekAndWrite_UpdatesHeader(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"aflushseek_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        CreateTestFile(path, 1000, blockSize);

        var overwrite = new byte[100];
        for (int i = 0; i < 100; i++)
            overwrite[i] = 0xDD;

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(200, SeekOrigin.Begin);
            await stream.WriteAsync(overwrite, 0, overwrite.Length);
            await stream.FlushAsync();
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1000);

            stream.Seek(200, SeekOrigin.Begin);
            var buf = new byte[100];
            int totalRead = 0;
            while (totalRead < 100)
            {
                int r = await stream.ReadAsync(buf, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(100);
            buf.Should().OnlyContain(b => b == 0xDD);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task DisposeAsync_FlushesUnflushedData(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"adisposeflush_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 1024);
        await using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
            // No flush — rely on DisposeAsync
        }

        await using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1024);
            var buf = new byte[1024];
            int totalRead = 0;
            while (totalRead < 1024)
            {
                int r = await stream.ReadAsync(buf, totalRead, 1024 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(1024);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task DisposeAsync_MultipleDisposes_NoError(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"amultidispose_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var stream = _factory.Create(path, FileMode.Create, options);
        await stream.WriteAsync(new byte[] { 0x01 }, 0, 1);
        await stream.DisposeAsync();

        Func<Task> act = async () => await stream.DisposeAsync();
        await act.Should().NotThrowAsync();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task InterleavedAsyncReadWrite_DataConsistent(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"ainterleaved2_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 1024);
        using var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options);

        // Write 1KB
        await stream.WriteAsync(data, 0, data.Length);
        await stream.FlushAsync();

        // Seek to start, read first 500 bytes
        stream.Seek(0, SeekOrigin.Begin);
        var readBuf = new byte[500];
        int totalRead = 0;
        while (totalRead < 500)
        {
            int r = await stream.ReadAsync(readBuf, totalRead, 500 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(500);
        readBuf.Should().BeEquivalentTo(ExpectedPattern(0, 500));

        // Write 500 bytes at current position (500)
        var newData = new byte[500];
        for (int i = 0; i < 500; i++)
            newData[i] = 0xEE;
        await stream.WriteAsync(newData, 0, newData.Length);
        await stream.FlushAsync();

        // Verify overwritten data
        stream.Seek(500, SeekOrigin.Begin);
        var verifyBuf = new byte[500];
        totalRead = 0;
        while (totalRead < 500)
        {
            int r = await stream.ReadAsync(verifyBuf, totalRead, 500 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(500);
        verifyBuf.Should().OnlyContain(b => b == 0xEE);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public async Task LargeFileAsync_DataIntegrity(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"alarge_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        const int fileSize = 500 * 1024; // 500KB
        var data = new byte[fileSize];
        Random.Shared.NextBytes(data);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(fileSize);

            var result = new byte[fileSize];
            int totalRead = 0;
            const int chunkSize = 65536;
            while (totalRead < fileSize)
            {
                int toRead = Math.Min(chunkSize, fileSize - totalRead);
                int r = await stream.ReadAsync(result, totalRead, toRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(fileSize);

            var expectedHash = System.Security.Cryptography.SHA256.HashData(data);
            var actualHash = System.Security.Cryptography.SHA256.HashData(result);
            actualHash.Should().BeEquivalentTo(expectedHash);
        }
    }
}
