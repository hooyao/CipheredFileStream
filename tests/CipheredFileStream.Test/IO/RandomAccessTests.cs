using FluentAssertions;
using CipheredFileStream.IO;

namespace CipheredFileStream.Test.IO;

public class RandomAccessTests : CryptoTestBase
{
    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RandomAccess_WriteAndRead(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"ra_{blockSize}.enc");
        var options = new CipheredFileStreamOptions
        {
            BlockSize = blockSize,
            AccessPattern = AccessPattern.RandomAccess
        };

        var data = GenerateRandomData(10_000);

        using (var s = _factory.Create(path, FileMode.Create, options))
        {
            s.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RandomAccess_OverwriteData(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"overwrite_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize, AccessPattern = AccessPattern.RandomAccess };

        // Write initial data
        using (var s = _factory.Create(path, FileMode.Create, options))
        {
            s.Write(new byte[1000], 0, 1000); // all zeros
        }

        // Overwrite bytes 500-509 with 0xFF
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            s.Seek(500, SeekOrigin.Begin);
            s.Write(Enumerable.Repeat((byte)0xFF, 10).ToArray(), 0, 10);
        }

        // Read back and verify
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            var buf = new byte[1000];
            s.Read(buf, 0, 1000);

            for (int i = 0; i < 500; i++)
                buf[i].Should().Be(0);
            for (int i = 500; i < 510; i++)
                buf[i].Should().Be(0xFF);
            for (int i = 510; i < 1000; i++)
                buf[i].Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void AsyncReadWrite_RoundTrips(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"async_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = GenerateRandomData(5000);

        using (var s = _factory.Create(path, FileMode.Create, options))
        {
            s.WriteAsync(data, 0, data.Length).Wait();
            s.FlushAsync().Wait();
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.ReadAsync(readBack, totalRead, readBack.Length - totalRead).Result;
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(data.Length);
        }

        readBack.Should().BeEquivalentTo(data);
    }
}
