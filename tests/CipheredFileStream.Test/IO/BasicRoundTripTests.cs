using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class BasicRoundTripTests : CryptoTestBase
{
    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WriteAndRead_SmallData(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"small_{blockSize}.enc");
        var data = GenerateRandomData(100);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Read(readBack, 0, readBack.Length).Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WriteAndRead_MultiBlock(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"multi_{blockSize}.enc");
        // Data large enough to span multiple blocks
        var data = GenerateRandomData(50_000);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int read = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EmptyFile_HasZeroLength(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"empty_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            // Write nothing
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(0);
            stream.Read(new byte[1], 0, 1).Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void SingleByte_RoundTrips(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"single_{blockSize}.enc");
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
    public void Length_IsCorrect_AfterWrite(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"len_{blockSize}.enc");
        var data = GenerateRandomData(12345);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
            stream.Length.Should().Be(12345);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(12345);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void LargeWrite_1MB_RoundTrips(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"large_{blockSize}.enc");
        var data = GenerateRandomData(1024 * 1024);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int read = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void SetLength_Truncate_Then_Write(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"truncwrite_{blockSize}.enc");
        var data = GenerateRandomData(10_240);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
            stream.SetLength(5000);
            stream.Position = 5000;
            var extra = GenerateRandomData(100);
            stream.Write(extra, 0, extra.Length);
            stream.Length.Should().Be(5100);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(5100);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void SetLength_Extend_Then_Read(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"extend_{blockSize}.enc");
        var data = GenerateRandomData(100);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
            stream.SetLength(1000);
        }

        var readBack = new byte[1000];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1000);
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int read = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(1000);
        }

        readBack.AsSpan(0, 100).ToArray().Should().BeEquivalentTo(data);
        readBack.AsSpan(100, 900).ToArray().Should().AllBeEquivalentTo((byte)0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WriteByte_Stress_1000Bytes(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"wbstress_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var expected = GenerateRandomData(1000);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            for (int i = 0; i < 1000; i++)
                stream.WriteByte(expected[i]);
        }

        var readBack = new byte[1000];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int read = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(1000);
        }

        readBack.Should().BeEquivalentTo(expected);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void MultipleFlush(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        var path = GetTestFilePath($"multiflush_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        // Write enough data to fill at least 2 full blocks, then flush, then write more
        var firstChunkSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;
        var secondChunkSize = 1024;
        var totalSize = firstChunkSize + secondChunkSize;
        var data = GenerateRandomData(totalSize);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, firstChunkSize);
            stream.Flush();
            stream.Write(data, firstChunkSize, secondChunkSize);
            stream.Flush();
        }

        var readBack = new byte[totalSize];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(totalSize);
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int read = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(totalSize);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void OpenOrCreate_NewFile(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"ocnew_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = GenerateRandomData(500);

        using (var stream = _factory.Create(path, FileMode.OpenOrCreate, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var readBack = new byte[500];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(500);
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int read = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(500);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void OpenOrCreate_ExistingFile(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"ocexist_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = GenerateRandomData(750);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.OpenOrCreate, options))
        {
            stream.Length.Should().Be(750);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Reopen_ReadWrite_ModifyAndVerify(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"reopen_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = GenerateRandomData(1024);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var patch = GenerateRandomData(100);
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Position = 0;
            stream.Write(patch, 0, patch.Length);
        }

        var readBack = new byte[1024];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(1024);
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int read = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(1024);
        }

        readBack.AsSpan(0, 100).ToArray().Should().BeEquivalentTo(patch);
        readBack.AsSpan(100, 924).ToArray().Should().BeEquivalentTo(data.AsSpan(100, 924).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ReadByte_AtEOF_ReturnsMinusOne(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"rbeof_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = GenerateRandomData(10);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Position = stream.Length;
            stream.ReadByte().Should().Be(-1);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Position_BeyondLength_ReadReturnsZero(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"posbeyond_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = GenerateRandomData(100);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Position = 200;
            var buf = new byte[10];
            stream.Read(buf, 0, buf.Length).Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Length_UpdatesAfterWrite(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"lenupdate_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Length.Should().Be(0);

            var data1 = GenerateRandomData(500);
            stream.Write(data1, 0, data1.Length);
            stream.Length.Should().Be(500);

            var data2 = GenerateRandomData(500);
            stream.Write(data2, 0, data2.Length);
            stream.Length.Should().Be(1000);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_ReadBack_SmallBuffer(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"smallbuf_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = GenerateRandomData(10_240);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            int totalRead = 0;
            var buf = new byte[7];
            while (totalRead < readBack.Length)
            {
                int toRead = Math.Min(buf.Length, readBack.Length - totalRead);
                int read = stream.Read(buf, 0, toRead);
                if (read == 0) break;
                Array.Copy(buf, 0, readBack, totalRead, read);
                totalRead += read;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ChunkedWrite_ReadBack(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"chunked_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = GenerateRandomData(50_000);
        int chunkSize = 3333;

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            int offset = 0;
            while (offset < data.Length)
            {
                int toWrite = Math.Min(chunkSize, data.Length - offset);
                stream.Write(data, offset, toWrite);
                offset += toWrite;
            }
        }

        var readBack = new byte[data.Length];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(data.Length);
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int read = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }
}
