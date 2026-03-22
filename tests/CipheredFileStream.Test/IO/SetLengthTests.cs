using FluentAssertions;
using CipheredFileStream.IO;

namespace CipheredFileStream.Test.IO;

public class SetLengthTests : CryptoTestBase
{
    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Truncate_ReducesLength(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"trunc_{blockSize}.enc");
        var data = GenerateRandomData(10_000);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
        {
            s.Write(data, 0, data.Length);
            s.SetLength(5000);
            s.Length.Should().Be(5000);
        }

        // Verify on reopen
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Length.Should().Be(5000);

        var readBack = new byte[5000];
        int totalRead = 0;
        while (totalRead < 5000)
        {
            int r = stream.Read(readBack, totalRead, 5000 - totalRead);
            if (r == 0) break;
            totalRead += r;
        }
        totalRead.Should().Be(5000);
        readBack.Should().BeEquivalentTo(data.AsSpan(0, 5000).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void SetLength_Zero_EmptiesFile(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"zero_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
        {
            s.Write(GenerateRandomData(5000), 0, 5000);
            s.SetLength(0);
            s.Length.Should().Be(0);
        }

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Length.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Extend_FillsWithZeros(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"extend_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
        {
            s.Write(new byte[] { 1, 2, 3 }, 0, 3);
            s.SetLength(100);
            s.Length.Should().Be(100);
        }

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Length.Should().Be(100);
        var buf = new byte[100];
        stream.ReadExactly(buf, 0, 100);

        // First 3 bytes are original data
        buf[0].Should().Be(1);
        buf[1].Should().Be(2);
        buf[2].Should().Be(3);
        // Rest are zeros
        for (int i = 3; i < 100; i++)
            buf[i].Should().Be(0, $"byte at index {i} should be zero");
    }
}
