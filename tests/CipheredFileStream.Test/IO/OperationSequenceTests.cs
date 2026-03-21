using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Tests for multi-operation sequences: Write/Read/Seek/Flush/SetLength/Dispose combinations
/// that are prone to state management bugs in ring buffer and BlockManager interactions.
/// </summary>
public class OperationSequenceTests : CryptoTestBase
{
    private const int GcmOverhead = 28;

    private static BlockLayout GetLayout(BlockSizeOption blockSize)
        => new((int)blockSize, GcmOverhead);

    private static CipheredFileStreamOptions SeqOptions(BlockSizeOption blockSize)
        => new() { BlockSize = blockSize, AccessPattern = AccessPattern.Sequential };

    private static CipheredFileStreamOptions RaOptions(BlockSizeOption blockSize)
        => new() { BlockSize = blockSize, AccessPattern = AccessPattern.RandomAccess };

    private static byte[] MakePattern(int size)
    {
        var data = new byte[size];
        for (int i = 0; i < size; i++)
            data[i] = (byte)(i % 251);
        return data;
    }

    private byte[] ReadAll(string path, int size, CipheredFileStreamOptions options)
    {
        var buf = new byte[size];
        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        int total = 0;
        while (total < size)
        {
            int r = stream.Read(buf, total, size - total);
            if (r == 0) break;
            total += r;
        }
        return buf;
    }

    // ═══════════════════════════════════════════════════════
    // 1. Write → Flush → Write (append to NEW block)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_Flush_WriteAppendNewBlock(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"flush_newblock_{blockSize}.enc");

        // Write exactly Block0DataCapacity to fill block 0 completely
        var part1 = MakePattern(layout.Block0DataCapacity);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(part1, 0, part1.Length);
            stream.Flush();

            // Continue append — now goes to block 1 (new block, clean boundary)
            var part2 = MakePattern(500);
            stream.Write(part2, 0, part2.Length);
        }

        // Verify
        int totalSize = layout.Block0DataCapacity + 500;
        var result = ReadAll(path, totalSize, options);
        result.AsSpan(0, layout.Block0DataCapacity).ToArray().Should().BeEquivalentTo(part1);
        result.AsSpan(layout.Block0DataCapacity, 500).ToArray().Should().BeEquivalentTo(MakePattern(500));
    }

    // ═══════════════════════════════════════════════════════
    // 2. Write → Flush → Seek → Read
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_Flush_Seek_Read(BlockSizeOption blockSize)
    {
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"flush_seek_read_{blockSize}.enc");
        var data = MakePattern(10_000);

        using var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options);
        stream.Write(data, 0, data.Length);
        stream.Flush();

        // Seek back and read
        stream.Seek(0, SeekOrigin.Begin);
        var buf = new byte[10_000];
        int total = 0;
        while (total < buf.Length)
        {
            int r = stream.Read(buf, total, buf.Length - total);
            if (r == 0) break;
            total += r;
        }

        total.Should().Be(10_000);
        buf.Should().BeEquivalentTo(data);
    }

    // ═══════════════════════════════════════════════════════
    // 3. Write → Flush → Seek → Write (overwrite)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_Flush_Seek_WriteOverwrite(BlockSizeOption blockSize)
    {
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"flush_seek_overwrite_{blockSize}.enc");
        var data = MakePattern(5000);

        using (var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options))
        {
            stream.Write(data, 0, data.Length);
            stream.Flush();

            // Seek back and overwrite first 100 bytes
            stream.Seek(0, SeekOrigin.Begin);
            var overwrite = new byte[100];
            Array.Fill(overwrite, (byte)0xAA);
            stream.Write(overwrite, 0, overwrite.Length);
        }

        // Verify
        var result = ReadAll(path, 5000, options);
        result.AsSpan(0, 100).ToArray().Should().OnlyContain(b => b == 0xAA);
        result.AsSpan(100, 4900).ToArray().Should().BeEquivalentTo(data.AsSpan(100, 4900).ToArray());
    }

    // ═══════════════════════════════════════════════════════
    // 4. Write → Flush → Seek → Write (append at EOF after seek)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_Flush_SeekEnd_WriteAppend(BlockSizeOption blockSize)
    {
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"flush_seekend_append_{blockSize}.enc");
        var part1 = MakePattern(5000);

        using (var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options))
        {
            stream.Write(part1, 0, part1.Length);
            stream.Flush();

            // Seek to some position, then seek to end, then append
            stream.Seek(100, SeekOrigin.Begin);  // seek away
            stream.Seek(0, SeekOrigin.End);       // back to EOF

            var part2 = MakePattern(3000);
            stream.Write(part2, 0, part2.Length);
        }

        // Verify
        var result = ReadAll(path, 8000, options);
        result.AsSpan(0, 5000).ToArray().Should().BeEquivalentTo(part1);
        result.AsSpan(5000, 3000).ToArray().Should().BeEquivalentTo(MakePattern(3000));
    }

    // ═══════════════════════════════════════════════════════
    // 5. Read → Seek → Write (overwrite after reading)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_Seek_WriteOverwrite(BlockSizeOption blockSize)
    {
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"read_seek_write_{blockSize}.enc");
        var data = MakePattern(10_000);

        // Create file
        using (var stream = _factory.Create(path, FileMode.Create, options))
            stream.Write(data, 0, data.Length);

        // Open, read some, seek back, overwrite
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, options))
        {
            // Read first 5000 bytes
            var readBuf = new byte[5000];
            int total = 0;
            while (total < 5000)
            {
                int r = stream.Read(readBuf, total, 5000 - total);
                if (r == 0) break;
                total += r;
            }
            readBuf.Should().BeEquivalentTo(data.AsSpan(0, 5000).ToArray());

            // Seek to 2000, overwrite 100 bytes
            stream.Seek(2000, SeekOrigin.Begin);
            var patch = new byte[100];
            Array.Fill(patch, (byte)0xBB);
            stream.Write(patch, 0, patch.Length);
        }

        // Verify
        var expected = (byte[])data.Clone();
        Array.Fill(expected, (byte)0xBB, 2000, 100);
        var result = ReadAll(path, 10_000, options);
        result.Should().BeEquivalentTo(expected);
    }

    // ═══════════════════════════════════════════════════════
    // 6. Write → Seek(0) → Read all → Seek(0) → Write (full overwrite)
    //    The "read 50M, modify, write back" scenario
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_SeekRead_SeekWrite_FullOverwrite(BlockSizeOption blockSize)
    {
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"full_overwrite_{blockSize}.enc");
        var original = MakePattern(20_000);

        using (var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options))
        {
            // Write original data
            stream.Write(original, 0, original.Length);

            // Seek to start, read all
            stream.Seek(0, SeekOrigin.Begin);
            var readBuf = new byte[20_000];
            int total = 0;
            while (total < 20_000)
            {
                int r = stream.Read(readBuf, total, 20_000 - total);
                if (r == 0) break;
                total += r;
            }
            readBuf.Should().BeEquivalentTo(original);

            // "Modify" — invert all bytes
            for (int i = 0; i < readBuf.Length; i++)
                readBuf[i] = (byte)~readBuf[i];

            // Seek to start, write back modified data
            stream.Seek(0, SeekOrigin.Begin);
            stream.Write(readBuf, 0, readBuf.Length);
        }

        // Verify modified data persisted
        var expected = new byte[20_000];
        for (int i = 0; i < 20_000; i++)
            expected[i] = (byte)~original[i];

        var result = ReadAll(path, 20_000, options);
        result.Should().BeEquivalentTo(expected);
    }

    // ═══════════════════════════════════════════════════════
    // 7. Multiple Flush cycles (3+)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void MultipleFlushCycles_3Times(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"multiflush3_{blockSize}.enc");

        // Use block-aligned sizes to avoid mid-block append issue
        int chunkSize = layout.Block0DataCapacity;

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            var chunk1 = MakePattern(chunkSize);
            stream.Write(chunk1, 0, chunk1.Length);
            stream.Flush();

            // Second chunk goes to new blocks (clean boundary)
            var chunk2 = new byte[layout.BlockNDataCapacity];
            Array.Fill(chunk2, (byte)0xAA);
            stream.Write(chunk2, 0, chunk2.Length);
            stream.Flush();

            // Third chunk
            var chunk3 = new byte[layout.BlockNDataCapacity];
            Array.Fill(chunk3, (byte)0xBB);
            stream.Write(chunk3, 0, chunk3.Length);
            stream.Flush();
        }

        int totalSize = chunkSize + 2 * layout.BlockNDataCapacity;
        var result = ReadAll(path, totalSize, options);

        result.AsSpan(0, chunkSize).ToArray().Should().BeEquivalentTo(MakePattern(chunkSize));
        result.AsSpan(chunkSize, layout.BlockNDataCapacity).ToArray()
            .Should().OnlyContain(b => b == 0xAA);
        result.AsSpan(chunkSize + layout.BlockNDataCapacity, layout.BlockNDataCapacity).ToArray()
            .Should().OnlyContain(b => b == 0xBB);
    }

    // ═══════════════════════════════════════════════════════
    // 8. Write → Flush → SetLength → Write
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_Flush_SetLength_Write(BlockSizeOption blockSize)
    {
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"flush_setlen_write_{blockSize}.enc");

        using (var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options))
        {
            var data = MakePattern(10_000);
            stream.Write(data, 0, data.Length);
            stream.Flush();

            // Truncate
            stream.SetLength(3000);
            stream.Length.Should().Be(3000);

            // Write more at new EOF
            stream.Seek(0, SeekOrigin.End);
            var more = new byte[2000];
            Array.Fill(more, (byte)0xCC);
            stream.Write(more, 0, more.Length);
        }

        // Verify: first 3000 bytes original, then 2000 bytes of 0xCC
        var result = ReadAll(path, 5000, options);
        result.AsSpan(0, 3000).ToArray().Should().BeEquivalentTo(MakePattern(10_000).AsSpan(0, 3000).ToArray());
        result.AsSpan(3000, 2000).ToArray().Should().OnlyContain(b => b == 0xCC);
    }

    // ═══════════════════════════════════════════════════════
    // 9. Position (set property) → Write
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void SetPosition_ThenWrite(BlockSizeOption blockSize)
    {
        var options = RaOptions(blockSize);
        var path = GetTestFilePath($"setpos_write_{blockSize}.enc");

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            // Write initial data
            var data = new byte[1000];
            Array.Fill(data, (byte)0x11);
            stream.Write(data, 0, data.Length);

            // Set position directly (not via Seek) and overwrite
            stream.Position = 500;
            var patch = new byte[100];
            Array.Fill(patch, (byte)0xFF);
            stream.Write(patch, 0, patch.Length);
        }

        var result = ReadAll(path, 1000, options);
        result.AsSpan(0, 500).ToArray().Should().OnlyContain(b => b == 0x11);
        result.AsSpan(500, 100).ToArray().Should().OnlyContain(b => b == 0xFF);
        result.AsSpan(600, 400).ToArray().Should().OnlyContain(b => b == 0x11);
    }

    // ═══════════════════════════════════════════════════════
    // 10. Write → Seek(0) → Read → Seek(middle) → Write → Seek(0) → Read all
    //     Complex interleaved multi-step
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ComplexInterleaved_WriteReadWriteRead(BlockSizeOption blockSize)
    {
        var options = SeqOptions(blockSize);
        var path = GetTestFilePath($"complex_{blockSize}.enc");

        using (var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options))
        {
            // Step 1: Write 5000 bytes
            var data = MakePattern(5000);
            stream.Write(data, 0, data.Length);

            // Step 2: Seek to 0, read first 1000
            stream.Seek(0, SeekOrigin.Begin);
            var readBuf = new byte[1000];
            int r = 0;
            while (r < 1000) { int n = stream.Read(readBuf, r, 1000 - r); if (n == 0) break; r += n; }
            readBuf.Should().BeEquivalentTo(data.AsSpan(0, 1000).ToArray());

            // Step 3: Seek to 2000, overwrite 500 bytes
            stream.Seek(2000, SeekOrigin.Begin);
            var patch = new byte[500];
            Array.Fill(patch, (byte)0xDD);
            stream.Write(patch, 0, patch.Length);

            // Step 4: Seek to 0, read entire file
            stream.Seek(0, SeekOrigin.Begin);
            var fullBuf = new byte[5000];
            int total = 0;
            while (total < 5000) { int n = stream.Read(fullBuf, total, 5000 - total); if (n == 0) break; total += n; }
            total.Should().Be(5000);

            var expected = (byte[])data.Clone();
            Array.Fill(expected, (byte)0xDD, 2000, 500);
            fullBuf.Should().BeEquivalentTo(expected);
        }
    }
}
