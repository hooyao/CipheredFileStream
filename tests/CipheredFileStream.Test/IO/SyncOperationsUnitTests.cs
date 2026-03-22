using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class SyncOperationsUnitTests : CryptoTestBase
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
    public void Read_EmptyFile_ReturnsZero(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"empty_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            // Write nothing — empty file
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            var buf = new byte[100];
            stream.Read(buf, 0, buf.Length).Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_SingleByte_AtPosition0(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"single_{blockSize}.enc");
        CreateTestFile(path, 1, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var buf = new byte[1];
        stream.Read(buf, 0, 1).Should().Be(1);
        buf[0].Should().Be(0); // 0 % 251 == 0
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_WithinBlock0(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity; // fill block 0 completely
        var path = GetTestFilePath($"within0_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Seek(50, SeekOrigin.Begin);

        var buf = new byte[100];
        stream.Read(buf, 0, 100).Should().Be(100);
        buf.Should().BeEquivalentTo(ExpectedPattern(50, 100));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_ExactlyBlock0Capacity(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int cap = layout.Block0DataCapacity;
        var path = GetTestFilePath($"exact0_{blockSize}.enc");
        CreateTestFile(path, cap, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var buf = new byte[cap];
        int totalRead = 0;
        while (totalRead < cap)
        {
            int r = stream.Read(buf, totalRead, cap - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(cap);
        buf.Should().BeEquivalentTo(ExpectedPattern(0, cap));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_CrossingBlock0ToBlock1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;
        var path = GetTestFilePath($"cross01_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        // Read starting 50 bytes before block 0 ends, spanning into block 1
        int readStart = layout.Block0DataCapacity - 50;
        stream.Seek(readStart, SeekOrigin.Begin);

        var buf = new byte[200];
        int totalRead = 0;
        while (totalRead < 200)
        {
            int r = stream.Read(buf, totalRead, 200 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(200);
        buf.Should().BeEquivalentTo(ExpectedPattern(readStart, 200));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_EntireBlock1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;
        var path = GetTestFilePath($"block1_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        int block1Start = layout.Block0DataCapacity;
        stream.Seek(block1Start, SeekOrigin.Begin);

        var buf = new byte[layout.BlockNDataCapacity];
        int totalRead = 0;
        while (totalRead < buf.Length)
        {
            int r = stream.Read(buf, totalRead, buf.Length - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(layout.BlockNDataCapacity);
        buf.Should().BeEquivalentTo(ExpectedPattern(block1Start, layout.BlockNDataCapacity));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_CrossingBlock1ToBlock2(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + 2 * layout.BlockNDataCapacity;
        var path = GetTestFilePath($"cross12_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        // Read spanning from end of block 1 into block 2
        int readStart = layout.Block0DataCapacity + layout.BlockNDataCapacity - 50;
        stream.Seek(readStart, SeekOrigin.Begin);

        var buf = new byte[200];
        int totalRead = 0;
        while (totalRead < 200)
        {
            int r = stream.Read(buf, totalRead, 200 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(200);
        buf.Should().BeEquivalentTo(ExpectedPattern(readStart, 200));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_FromMiddleOfBlock2(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + 3 * layout.BlockNDataCapacity;
        var path = GetTestFilePath($"mid2_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        int readStart = layout.Block0DataCapacity + layout.BlockNDataCapacity + layout.BlockNDataCapacity / 2;
        stream.Seek(readStart, SeekOrigin.Begin);

        var buf = new byte[256];
        int totalRead = 0;
        while (totalRead < 256)
        {
            int r = stream.Read(buf, totalRead, 256 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(256);
        buf.Should().BeEquivalentTo(ExpectedPattern(readStart, 256));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_EntireFile_InChunks(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + 3 * layout.BlockNDataCapacity;
        var path = GetTestFilePath($"chunks_{blockSize}.enc");
        CreateTestFile(path, fileSize, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var result = new byte[fileSize];
        int totalRead = 0;
        const int chunkSize = 65536;
        while (totalRead < fileSize)
        {
            int toRead = Math.Min(chunkSize, fileSize - totalRead);
            int r = stream.Read(result, totalRead, toRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(fileSize);
        result.Should().BeEquivalentTo(ExpectedPattern(0, fileSize));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_BeyondEOF_ReturnsPartial(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"eof_{blockSize}.enc");
        CreateTestFile(path, 100, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        stream.Seek(80, SeekOrigin.Begin);
        var buf = new byte[100];
        int totalRead = 0;
        while (totalRead < 100)
        {
            int r = stream.Read(buf, totalRead, 100 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(20); // only 20 bytes remaining from position 80
        buf.AsSpan(0, 20).ToArray().Should().BeEquivalentTo(ExpectedPattern(80, 20));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_SingleByte_Verify(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"w1_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.WriteByte(0xAB);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1);
            stream.ReadByte().Should().Be(0xAB);
            stream.ReadByte().Should().Be(-1); // EOF
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_FillBlock0_Verify(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int cap = layout.Block0DataCapacity;
        var path = GetTestFilePath($"fill0_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, cap);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(cap);
            var buf = new byte[cap];
            int totalRead = 0;
            while (totalRead < cap)
            {
                int r = stream.Read(buf, totalRead, cap - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(cap);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_CrossBlock0ToBlock1_Verify(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int size = layout.Block0DataCapacity + 100;
        var path = GetTestFilePath($"wcross01_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, size);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(size);
            var buf = new byte[size];
            int totalRead = 0;
            while (totalRead < size)
            {
                int r = stream.Read(buf, totalRead, size - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(size);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_MultipleBlocks_Verify(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int size = layout.Block0DataCapacity + 3 * layout.BlockNDataCapacity + 500;
        var path = GetTestFilePath($"wmulti_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, size);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(size);
            var buf = new byte[size];
            int totalRead = 0;
            while (totalRead < size)
            {
                int r = stream.Read(buf, totalRead, size - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(size);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_SmallChunks_1ByteAtATime_First100Bytes(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"w1byte_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            for (int i = 0; i < 100; i++)
                stream.WriteByte((byte)(i % 251));
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(100);
            var buf = new byte[100];
            int totalRead = 0;
            while (totalRead < 100)
            {
                int r = stream.Read(buf, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(100);
            buf.Should().BeEquivalentTo(ExpectedPattern(0, 100));
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_WithOffset(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"roffset_{blockSize}.enc");
        CreateTestFile(path, 1024, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var buf = new byte[200];
        int read = stream.Read(buf, 50, 100);
        read.Should().BeGreaterThan(0);

        // Read remaining if partial
        int totalRead = read;
        while (totalRead < 100)
        {
            int r = stream.Read(buf, 50 + totalRead, 100 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(100);
        buf.AsSpan(50, 100).ToArray().Should().BeEquivalentTo(ExpectedPattern(0, 100));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_Span(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"rspan_{blockSize}.enc");
        CreateTestFile(path, 1024, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        Span<byte> buf = new byte[256];
        int totalRead = 0;
        while (totalRead < 256)
        {
            int r = stream.Read(buf.Slice(totalRead));
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(256);
        buf.ToArray().Should().BeEquivalentTo(ExpectedPattern(0, 256));
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_ZeroCount_ReturnsZero(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"rzero_{blockSize}.enc");
        CreateTestFile(path, 100, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        var buf = new byte[100];
        stream.Read(buf, 0, 0).Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ReadByte_ReturnsCorrectValue(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"rbyte_{blockSize}.enc");
        CreateTestFile(path, 1024, blockSize);

        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);

        // Check position 0
        stream.ReadByte().Should().Be(0 % 251);

        // Seek to position 100
        stream.Seek(100, SeekOrigin.Begin);
        stream.ReadByte().Should().Be(100 % 251);

        // Seek to position 500
        stream.Seek(500, SeekOrigin.Begin);
        stream.ReadByte().Should().Be(500 % 251);

        // Seek to last byte
        stream.Seek(1023, SeekOrigin.Begin);
        stream.ReadByte().Should().Be(1023 % 251);

        // Beyond EOF
        stream.Seek(1024, SeekOrigin.Begin);
        stream.ReadByte().Should().Be(-1);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_WithOffset(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"woffset_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var source = new byte[200];
        for (int i = 0; i < 200; i++)
            source[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(source, 50, 100);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(100);
            var buf = new byte[100];
            int totalRead = 0;
            while (totalRead < 100)
            {
                int r = stream.Read(buf, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(100);
            // Data written was source[50..150]
            buf.Should().BeEquivalentTo(source.AsSpan(50, 100).ToArray());
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_Span(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"wspan_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 512);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data.AsSpan());
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(512);
            var buf = new byte[512];
            int totalRead = 0;
            while (totalRead < 512)
            {
                int r = stream.Read(buf, totalRead, 512 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(512);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_ZeroCount_NoChange(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"wzero_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            var buf = new byte[100];
            stream.Write(buf, 0, 0);
            stream.Length.Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WriteByte_PersistsCorrectly(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"wbyte_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.WriteByte(0x10);
            stream.WriteByte(0x20);
            stream.WriteByte(0x30);

            // Seek to position 100 and write there
            stream.Seek(100, SeekOrigin.Begin);
            stream.WriteByte(0xFF);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(101);
            stream.ReadByte().Should().Be(0x10);
            stream.ReadByte().Should().Be(0x20);
            stream.ReadByte().Should().Be(0x30);

            stream.Seek(100, SeekOrigin.Begin);
            stream.ReadByte().Should().Be(0xFF);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_AtPosition_Overwrites(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"woverwrite_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        CreateTestFile(path, 1024, blockSize);

        var overwrite = new byte[100];
        for (int i = 0; i < 100; i++)
            overwrite[i] = 0xAA;

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(200, SeekOrigin.Begin);
            stream.Write(overwrite, 0, overwrite.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1024);

            // Check data before overwrite region
            var before = new byte[200];
            int totalRead = 0;
            while (totalRead < 200)
            {
                int r = stream.Read(before, totalRead, 200 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            before.Should().BeEquivalentTo(ExpectedPattern(0, 200));

            // Check overwritten region
            var mid = new byte[100];
            totalRead = 0;
            while (totalRead < 100)
            {
                int r = stream.Read(mid, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            mid.Should().OnlyContain(b => b == 0xAA);

            // Check data after overwrite region
            var after = new byte[724];
            totalRead = 0;
            while (totalRead < 724)
            {
                int r = stream.Read(after, totalRead, 724 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(724);
            after.Should().BeEquivalentTo(ExpectedPattern(300, 724));
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_CrossingBlockBoundary_Overwrites(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;
        var path = GetTestFilePath($"wcrossoverwrite_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        CreateTestFile(path, fileSize, blockSize);

        // Write 100 bytes crossing the block 0/1 boundary
        int writeStart = layout.Block0DataCapacity - 50;
        var overwrite = new byte[100];
        for (int i = 0; i < 100; i++)
            overwrite[i] = 0xBB;

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(writeStart, SeekOrigin.Begin);
            stream.Write(overwrite, 0, overwrite.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(fileSize);

            // Verify data before overwrite
            stream.Seek(0, SeekOrigin.Begin);
            var before = new byte[writeStart];
            int totalRead = 0;
            while (totalRead < writeStart)
            {
                int r = stream.Read(before, totalRead, writeStart - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            before.Should().BeEquivalentTo(ExpectedPattern(0, writeStart));

            // Verify overwritten region
            var mid = new byte[100];
            totalRead = 0;
            while (totalRead < 100)
            {
                int r = stream.Read(mid, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            mid.Should().OnlyContain(b => b == 0xBB);

            // Verify data after overwrite
            int afterStart = writeStart + 100;
            int afterLen = fileSize - afterStart;
            var after = new byte[afterLen];
            totalRead = 0;
            while (totalRead < afterLen)
            {
                int r = stream.Read(after, totalRead, afterLen - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(afterLen);
            after.Should().BeEquivalentTo(ExpectedPattern(afterStart, afterLen));
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_BeyondEOF_ExtendsWithZeros(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"wbeyondeof_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        CreateTestFile(path, 1000, blockSize);

        var extra = new byte[100];
        for (int i = 0; i < 100; i++)
            extra[i] = 0xCC;

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(2000, SeekOrigin.Begin);
            stream.Write(extra, 0, extra.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(2100);

            // Original data intact
            var orig = new byte[1000];
            int totalRead = 0;
            while (totalRead < 1000)
            {
                int r = stream.Read(orig, totalRead, 1000 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            orig.Should().BeEquivalentTo(ExpectedPattern(0, 1000));

            // Gap should be zeros
            var gap = new byte[1000];
            totalRead = 0;
            while (totalRead < 1000)
            {
                int r = stream.Read(gap, totalRead, 1000 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(1000);
            gap.Should().OnlyContain(b => b == 0);

            // Written data at position 2000
            var written = new byte[100];
            totalRead = 0;
            while (totalRead < 100)
            {
                int r = stream.Read(written, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(100);
            written.Should().OnlyContain(b => b == 0xCC);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Flush_PersistsUnflushedData(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"flushpersist_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 500);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
            // No explicit flush — dispose should handle it
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(500);
            var buf = new byte[500];
            int totalRead = 0;
            while (totalRead < 500)
            {
                int r = stream.Read(buf, totalRead, 500 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(500);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Flush_MultipleFlushes_DataConsistent(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"multiflush_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data1 = ExpectedPattern(0, 500);
        var data2 = ExpectedPattern(500, 500);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data1, 0, data1.Length);
            stream.Flush();

            stream.Write(data2, 0, data2.Length);
            stream.Flush();
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1000);
            var buf = new byte[1000];
            int totalRead = 0;
            while (totalRead < 1000)
            {
                int r = stream.Read(buf, totalRead, 1000 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(1000);
            buf.Should().BeEquivalentTo(ExpectedPattern(0, 1000));
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Flush_AfterSeekAndWrite_UpdatesHeader(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"flushseek_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        CreateTestFile(path, 1000, blockSize);

        var overwrite = new byte[100];
        for (int i = 0; i < 100; i++)
            overwrite[i] = 0xDD;

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(200, SeekOrigin.Begin);
            stream.Write(overwrite, 0, overwrite.Length);
            stream.Flush();
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1000);

            stream.Seek(200, SeekOrigin.Begin);
            var buf = new byte[100];
            int totalRead = 0;
            while (totalRead < 100)
            {
                int r = stream.Read(buf, totalRead, 100 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(100);
            buf.Should().OnlyContain(b => b == 0xDD);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Dispose_FlushesUnflushedData(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"disposeflush_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 1024);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
            // No flush — rely on Dispose
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1024);
            var buf = new byte[1024];
            int totalRead = 0;
            while (totalRead < 1024)
            {
                int r = stream.Read(buf, totalRead, 1024 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(1024);
            buf.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Dispose_MultipleDisposes_NoError(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"multidispose_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var stream = _factory.Create(path, FileMode.Create, options);
        stream.WriteByte(0x01);
        stream.Dispose();

        var act = () => stream.Dispose();
        act.Should().NotThrow();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void InterleavedReadWrite_DataConsistent(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"interleaved_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        var data = ExpectedPattern(0, 1024);
        using var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options);

        // Write 1KB
        stream.Write(data, 0, data.Length);

        // Seek to start, read first 500 bytes
        stream.Seek(0, SeekOrigin.Begin);
        var readBuf = new byte[500];
        int totalRead = 0;
        while (totalRead < 500)
        {
            int r = stream.Read(readBuf, totalRead, 500 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(500);
        readBuf.Should().BeEquivalentTo(ExpectedPattern(0, 500));

        // Now write 500 bytes at current position (500)
        var newData = new byte[500];
        for (int i = 0; i < 500; i++)
            newData[i] = 0xEE;
        stream.Write(newData, 0, newData.Length);

        // Verify: seek to 500, read back the overwritten data
        stream.Seek(500, SeekOrigin.Begin);
        var verifyBuf = new byte[500];
        totalRead = 0;
        while (totalRead < 500)
        {
            int r = stream.Read(verifyBuf, totalRead, 500 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(500);
        verifyBuf.Should().OnlyContain(b => b == 0xEE);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void LargeFile_DataIntegrity(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"large_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        const int fileSize = 500 * 1024; // 500KB
        var data = new byte[fileSize];
        Random.Shared.NextBytes(data);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
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
                int r = stream.Read(result, totalRead, toRead);
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
