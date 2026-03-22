using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class FileSizeEdgeCaseUnitTests : CryptoTestBase
{
    private byte[] WriteAndReadBack(string path, byte[] data, BlockSizeOption blockSize)
    {
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
                int r = stream.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(data.Length);
        }

        return readBack;
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_EmptyFile(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"empty_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(Array.Empty<byte>(), 0, 0);
        }

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(0);
            stream.Read(new byte[1], 0, 1).Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_SingleByte(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"single_{blockSize}.enc");
        var data = new byte[] { 0xAB };

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_ExactlyBlock0DataCapacity(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        var data = GenerateRandomData(layout.Block0DataCapacity);
        var path = GetTestFilePath($"b0exact_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_Block0DataCapacityPlusOne(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        var data = GenerateRandomData(layout.Block0DataCapacity + 1);
        var path = GetTestFilePath($"b0plus1_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_ExactlyTwoBlocks(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        var data = GenerateRandomData(layout.Block0DataCapacity + layout.BlockNDataCapacity);
        var path = GetTestFilePath($"twoblocks_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_TwoBlocksPlusOne(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        var data = GenerateRandomData(layout.Block0DataCapacity + layout.BlockNDataCapacity + 1);
        var path = GetTestFilePath($"twoblocksplus1_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_100KB(BlockSizeOption blockSize)
    {
        var data = GenerateRandomData(102400);
        var path = GetTestFilePath($"100kb_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_1MB(BlockSizeOption blockSize)
    {
        var data = GenerateRandomData(1048576);
        var path = GetTestFilePath($"1mb_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_Block0DataCapacityMinusOne(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        var data = GenerateRandomData(layout.Block0DataCapacity - 1);
        var path = GetTestFilePath($"b0minus1_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_ExactlyThreeBlocks(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        var data = GenerateRandomData(layout.Block0DataCapacity + 2 * layout.BlockNDataCapacity);
        var path = GetTestFilePath($"threeblocks_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void EdgeCase_SmallChunkedWrite(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"chunked_{blockSize}.enc");
        var data = GenerateRandomData(10240);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            int offset = 0;
            while (offset < data.Length)
            {
                int chunk = Math.Min(100, data.Length - offset);
                stream.Write(data, offset, chunk);
                offset += chunk;
            }
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
}
