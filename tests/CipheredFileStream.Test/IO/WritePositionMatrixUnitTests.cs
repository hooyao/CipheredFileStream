using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Systematic writes at various positions with verification.
/// Uses RandomAccess pattern. Creates initial file with zeros, then overwrites
/// specific regions and verifies correctness.
/// </summary>
public class WritePositionMatrixUnitTests : CryptoTestBase
{
    private const int GcmOverhead = 28;

    private static CipheredFileStreamOptions MakeOptions(BlockSizeOption blockSize) => new()
    {
        BlockSize = blockSize,
        AccessPattern = AccessPattern.RandomAccess,
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
    public void Write_FirstByte(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wfirst_{blockSize}.enc");

        // Create file with 1000 zero bytes
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(new byte[1000], 0, 1000);
        }

        // Write 0xFF at position 0
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(0, SeekOrigin.Begin);
            stream.WriteByte(0xFF);
        }

        var result = ReadAll(path, 1000, options);
        result[0].Should().Be(0xFF);
        result.Skip(1).Should().OnlyContain(b => b == 0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_FillBlock0Exactly(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wfillb0_{blockSize}.enc");
        int count = layout.Block0DataCapacity;

        var data = new byte[count];
        for (int i = 0; i < count; i++)
            data[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var result = ReadAll(path, count, options);
        result.Should().Equal(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_SpillToBlock1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wspill_{blockSize}.enc");
        int count = layout.Block0DataCapacity + 100;

        var data = new byte[count];
        for (int i = 0; i < count; i++)
            data[i] = (byte)(i % 239);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var result = ReadAll(path, count, options);
        result.Should().Equal(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_LastByteOfBlock0(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wlastb0_{blockSize}.enc");
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;

        // Create file filled with zeros
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(new byte[fileSize], 0, fileSize);
        }

        // Write 1 byte at the last position of block 0
        int position = layout.Block0DataCapacity - 1;
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(position, SeekOrigin.Begin);
            stream.WriteByte(0xAB);
        }

        var result = ReadAll(path, fileSize, options);
        result[position].Should().Be(0xAB);
        // Verify surrounding bytes are still zero
        if (position > 0) result[position - 1].Should().Be(0);
        result[position + 1].Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_CrossBlock0Block1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wcross01_{blockSize}.enc");
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;

        // Create file filled with zeros
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(new byte[fileSize], 0, fileSize);
        }

        // Write 100 bytes crossing the block 0/1 boundary
        int position = layout.Block0DataCapacity - 50;
        var writeData = new byte[100];
        for (int i = 0; i < 100; i++)
            writeData[i] = (byte)(0x80 + i);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(position, SeekOrigin.Begin);
            stream.Write(writeData, 0, writeData.Length);
        }

        var result = ReadAll(path, fileSize, options);

        // Bytes before the write should be zero
        result.Take(position).Should().OnlyContain(b => b == 0);
        // Written bytes should match
        result.Skip(position).Take(100).Should().Equal(writeData);
        // Bytes after the write should be zero
        result.Skip(position + 100).Should().OnlyContain(b => b == 0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_FirstByteOfBlock1(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wfirstb1_{blockSize}.enc");
        int fileSize = layout.Block0DataCapacity + layout.BlockNDataCapacity;

        // Create file filled with zeros
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(new byte[fileSize], 0, fileSize);
        }

        // Write at the first position of block 1
        int position = layout.Block0DataCapacity;
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(position, SeekOrigin.Begin);
            stream.WriteByte(0xCD);
        }

        var result = ReadAll(path, fileSize, options);
        result[position].Should().Be(0xCD);
        result[position - 1].Should().Be(0);
        if (position + 1 < fileSize)
            result[position + 1].Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_BeyondEOF_CreatesGap(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wgap_{blockSize}.enc");

        // Create a 1000-byte file
        var initialData = new byte[1000];
        for (int i = 0; i < 1000; i++)
            initialData[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(initialData, 0, initialData.Length);
        }

        // Write 10 bytes at position 2000 (beyond current EOF at 1000)
        var writeData = new byte[10];
        Array.Fill(writeData, (byte)0xEE);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(2000, SeekOrigin.Begin);
            stream.Write(writeData, 0, writeData.Length);
        }

        // Verify: file should now be 2010 bytes
        var result = ReadAll(path, 2010, options);
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
    public void Write_OverwriteMiddle_PreservesRest(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"wmiddle_{blockSize}.enc");

        // Create 1000-byte file with pattern data
        var data = new byte[1000];
        for (int i = 0; i < 1000; i++)
            data[i] = (byte)(i % 251);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        // Overwrite 100 bytes in the middle (positions 400-499)
        var overwrite = new byte[100];
        Array.Fill(overwrite, (byte)0xFF);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            stream.Seek(400, SeekOrigin.Begin);
            stream.Write(overwrite, 0, overwrite.Length);
        }

        var result = ReadAll(path, 1000, options);

        // First 400 bytes unchanged
        result.Take(400).Should().Equal(data.Take(400));
        // Middle 100 bytes overwritten
        result.Skip(400).Take(100).Should().OnlyContain(b => b == 0xFF);
        // Last 500 bytes unchanged
        result.Skip(500).Take(500).Should().Equal(data.Skip(500).Take(500));
    }
}
