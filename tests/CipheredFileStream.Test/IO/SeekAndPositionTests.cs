using FluentAssertions;
using CipheredFileStream.IO;

namespace CipheredFileStream.Test.IO;

public class SeekAndPositionTests : CryptoTestBase
{
    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Seek_Begin_ReadsCorrectly(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"seek_{blockSize}.enc");
        var data = GenerateRandomData(10_000);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.Write(data, 0, data.Length);

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Seek(5000, SeekOrigin.Begin);
        stream.Position.Should().Be(5000);

        var buf = new byte[100];
        stream.Read(buf, 0, 100).Should().Be(100);
        buf.Should().BeEquivalentTo(data.AsSpan(5000, 100).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Seek_Current_Works(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"seek_cur_{blockSize}.enc");
        var data = GenerateRandomData(1000);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.Write(data, 0, data.Length);

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.ReadExactly(new byte[100], 0, 100); // read 100 bytes
        stream.Position.Should().Be(100);

        stream.Seek(50, SeekOrigin.Current);
        stream.Position.Should().Be(150);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Seek_End_Works(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"seek_end_{blockSize}.enc");
        var data = GenerateRandomData(1000);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.Write(data, 0, data.Length);

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream.Seek(-10, SeekOrigin.End);
        stream.Position.Should().Be(990);

        var buf = new byte[10];
        stream.Read(buf, 0, 10).Should().Be(10);
        buf.Should().BeEquivalentTo(data.AsSpan(990, 10).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Position_SetGet_Works(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"pos_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Create, options);
        stream.Position = 500;
        stream.Position.Should().Be(500);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Seek_Negative_Throws(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"neg_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Create, options);
        var act = () => stream.Seek(-1, SeekOrigin.Begin);
        act.Should().Throw<IOException>();
    }
}
