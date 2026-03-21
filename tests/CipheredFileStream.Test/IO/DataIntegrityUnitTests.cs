using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Multi-operation integrity scenarios that verify data consistency across
/// writes, reads, reopens, and mixed access patterns.
/// </summary>
public class DataIntegrityUnitTests : CryptoTestBase
{
    private const int GcmOverhead = 28;

    private static CipheredFileStreamOptions MakeOptions(
        BlockSizeOption blockSize,
        AccessPattern access = AccessPattern.RandomAccess) => new()
    {
        BlockSize = blockSize,
        AccessPattern = access,
    };

    /// <summary>
    /// Helper: reads entire file content into a byte array.
    /// </summary>
    private byte[] ReadAll(string path, int expectedSize, CipheredFileStreamOptions options)
    {
        var buffer = new byte[expectedSize];
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        int totalRead = 0;
        while (totalRead < expectedSize)
        {
            int read = stream.Read(buffer, totalRead, expectedSize - totalRead);
            if (read == 0) break;
            totalRead += read;
        }
        return buffer.AsSpan(0, totalRead).ToArray();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void MultipleSmallWrites_IntegrityPreserved(BlockSizeOption blockSize)
    {
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"multismall_{blockSize}.enc");

        // Write 10 chunks of 1KB
        var chunks = new List<byte[]>();
        for (int i = 0; i < 10; i++)
        {
            var chunk = new byte[1024];
            new Random(i + 100).NextBytes(chunk);
            chunks.Add(chunk);
        }

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            foreach (var chunk in chunks)
                stream.Write(chunk, 0, chunk.Length);
        }

        var expected = chunks.SelectMany(c => c).ToArray();
        var result = ReadAll(path, expected.Length, options);

        result.Should().HaveCount(expected.Length);
        result.Should().Equal(expected);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void InterleavedReadWrite_RandomAccess(BlockSizeOption blockSize)
    {
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"interleaved_{blockSize}.enc");

        // Write 5KB of pattern data
        var data = new byte[5120];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        // Seek to 1000, read 100 bytes, then write 100 bytes at 2000
        var readBuf = new byte[100];
        var writeData = new byte[100];
        Array.Fill(writeData, (byte)0xBB);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(1000, SeekOrigin.Begin);
            int readCount = 0;
            while (readCount < 100)
            {
                int r = stream.Read(readBuf, readCount, 100 - readCount);
                if (r == 0) break;
                readCount += r;
            }
            readCount.Should().Be(100);
            readBuf.Should().Equal(data.AsSpan(1000, 100).ToArray());

            stream.Seek(2000, SeekOrigin.Begin);
            stream.Write(writeData, 0, writeData.Length);
        }

        // Build expected data
        var expected = (byte[])data.Clone();
        Array.Copy(writeData, 0, expected, 2000, 100);

        var result = ReadAll(path, expected.Length, options);
        result.Should().Equal(expected);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void PartialBlockUpdate(BlockSizeOption blockSize)
    {
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"partial_{blockSize}.enc");

        // Write 1000 bytes
        var data = new byte[1000];
        Array.Fill(data, (byte)'A');

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        // Reopen and overwrite bytes 400-499
        var overwrite = new byte[100];
        Array.Fill(overwrite, (byte)'B');

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(400, SeekOrigin.Begin);
            stream.Write(overwrite, 0, overwrite.Length);
        }

        // Reopen and verify all 1000 bytes
        var result = ReadAll(path, 1000, options);
        result.Take(400).Should().OnlyContain(b => b == (byte)'A');
        result.Skip(400).Take(100).Should().OnlyContain(b => b == (byte)'B');
        result.Skip(500).Take(500).Should().OnlyContain(b => b == (byte)'A');
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void FileReopen_5Times(BlockSizeOption blockSize)
    {
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"reopen5_{blockSize}.enc");

        var data = new byte[1024];
        new Random(42).NextBytes(data);

        // Write initial data
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        // Reopen, read, and verify 5 times
        for (int i = 0; i < 5; i++)
        {
            var result = ReadAll(path, data.Length, options);
            result.Should().Equal(data, $"iteration {i} should match original data");
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void LargeFile_100KB_Integrity(BlockSizeOption blockSize)
    {
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"large100k_{blockSize}.enc");

        var data = GenerateRandomData(100 * 1024);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var result = ReadAll(path, data.Length, options);
        result.Should().Equal(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void CrossBlockBoundaryUpdate(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"crossupdate_{blockSize}.enc");

        // Write enough data to span at least 3 blocks
        int dataSize = layout.Block0DataCapacity + 2 * layout.BlockNDataCapacity;
        var data = new byte[dataSize];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        // Overwrite 200 bytes spanning the block 0/1 boundary
        int position = layout.Block0DataCapacity - 100;
        var overwrite = new byte[200];
        Array.Fill(overwrite, (byte)0xCC);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(position, SeekOrigin.Begin);
            stream.Write(overwrite, 0, overwrite.Length);
        }

        // Build expected data
        var expected = (byte[])data.Clone();
        Array.Copy(overwrite, 0, expected, position, 200);

        var result = ReadAll(path, expected.Length, options);
        result.Should().Equal(expected);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void AlternatingReadWriteSameBlock(BlockSizeOption blockSize)
    {
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"altreadwrite_{blockSize}.enc");

        // Write 100 bytes of pattern data
        var initial = new byte[100];
        for (int i = 0; i < 100; i++)
            initial[i] = (byte)(i + 1);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(initial, 0, initial.Length);
        }

        // Reopen: seek to 0, read 50, then overwrite 50 bytes at position 50
        var readBuf = new byte[50];
        var overwrite = new byte[50];
        Array.Fill(overwrite, (byte)0xDD);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(0, SeekOrigin.Begin);
            int totalRead = 0;
            while (totalRead < 50)
            {
                int r = stream.Read(readBuf, totalRead, 50 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(50);
            readBuf.Should().Equal(initial.AsSpan(0, 50).ToArray());

            stream.Seek(50, SeekOrigin.Begin);
            stream.Write(overwrite, 0, overwrite.Length);
        }

        // Verify
        var result = ReadAll(path, 100, options);
        result.Take(50).Should().Equal(initial.AsSpan(0, 50).ToArray());
        result.Skip(50).Take(50).Should().OnlyContain(b => b == 0xDD);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void MultipleSessions_AppendData(BlockSizeOption blockSize)
    {
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"multiappend_{blockSize}.enc");

        // Session 1: write 500 bytes
        var part1 = new byte[500];
        for (int i = 0; i < 500; i++)
            part1[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(part1, 0, part1.Length);
        }

        // Session 2: reopen ReadWrite, seek to end, write 500 more bytes
        var part2 = new byte[500];
        for (int i = 0; i < 500; i++)
            part2[i] = (byte)((i + 100) % 251);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(0, SeekOrigin.End);
            stream.Write(part2, 0, part2.Length);
        }

        // Session 3: read back all 1000 bytes
        var result = ReadAll(path, 1000, options);
        result.Should().HaveCount(1000);
        result.Take(500).Should().Equal(part1);
        result.Skip(500).Take(500).Should().Equal(part2);
    }
}
