using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class SequentialBufferSmokeTests : CryptoTestBase
{
    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Smoke_WriteSequential_ReadSequential(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"seq_seq_{blockSize}.enc");
        var data = GenerateRandomData(51200);
        var options = new CipheredFileStreamOptions
        {
            BlockSize = blockSize,
            AccessPattern = AccessPattern.Sequential,
        };

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
                int r = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Smoke_MultiBlock_Sequential(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        int size = layout.Block0DataCapacity + 5 * layout.BlockNDataCapacity;
        var data = GenerateRandomData(size);
        var path = GetTestFilePath($"multiblock_{blockSize}.enc");
        var options = new CipheredFileStreamOptions
        {
            BlockSize = blockSize,
            AccessPattern = AccessPattern.Sequential,
        };

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
                int r = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Smoke_WriteSequential_ReadRandomAccess(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"seq_ra_{blockSize}.enc");
        var data = GenerateRandomData(51200);
        var writeOptions = new CipheredFileStreamOptions
        {
            BlockSize = blockSize,
            AccessPattern = AccessPattern.Sequential,
        };
        var readOptions = new CipheredFileStreamOptions
        {
            BlockSize = blockSize,
            AccessPattern = AccessPattern.RandomAccess,
        };

        using (var stream = _factory.Create(path, FileMode.Create, writeOptions))
        {
            stream.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, readOptions))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }
}
