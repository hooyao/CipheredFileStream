using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Tests for the ReadAheadBuffer / WriteBehindBuffer ring buffer implementation.
/// Covers file size boundaries, access pattern cross-combinations, buffer size
/// variations, sequential write edge cases, auto-fallback, and physical file size.
/// </summary>
public class SequentialBufferTests : CryptoTestBase
{
    // ───────────────────────── Helper methods ─────────────────────────

    private static CipheredFileStreamOptions SeqOptions(BlockSizeOption blockSize, int bufferSize = 0)
        => new CipheredFileStreamOptions
        {
            BlockSize = blockSize,
            AccessPattern = AccessPattern.Sequential,
            BufferSize = bufferSize,
        };

    private static CipheredFileStreamOptions RaOptions(BlockSizeOption blockSize)
        => new CipheredFileStreamOptions
        {
            BlockSize = blockSize,
            AccessPattern = AccessPattern.RandomAccess,
        };

    private byte[] WriteAndReadBack(string path, byte[] data, BlockSizeOption blockSize, int bufferSize = 0)
    {
        var opts = SeqOptions(blockSize, bufferSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
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

        return readBack;
    }

    private static byte[] MakeData(int size, int seed = 42)
    {
        var rng = new Random(seed);
        var data = new byte[size];
        rng.NextBytes(data);
        return data;
    }

    private static BlockLayout GetLayout(BlockSizeOption blockSize)
        => new BlockLayout((int)blockSize, AesGcmBlockCrypto.Overhead);

    // ═══════════════════════════════════════════════════════════════════
    // 1. File Size Boundaries
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_ZeroBytes(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"zero_{blockSize}.enc");
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            // Write nothing
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(0);
            s.Read(new byte[1], 0, 1).Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_OneByte(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"one_{blockSize}.enc");
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.WriteByte(0xAB);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(1);
            s.ReadByte().Should().Be(0xAB);
            s.ReadByte().Should().Be(-1); // EOF
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_Block0DataCapacityMinusOne(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity - 1;
        var data = MakeData(size);
        var path = GetTestFilePath($"b0m1_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_ExactlyBlock0DataCapacity(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"b0exact_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_Block0DataCapacityPlusOne(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity + 1; // spills to block 1
        var data = MakeData(size);
        var path = GetTestFilePath($"b0p1_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_Block0PlusBlockN(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity + layout.BlockNDataCapacity; // exactly 2 blocks
        var data = MakeData(size);
        var path = GetTestFilePath($"b0bn_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_Block0PlusBlockNPlusOne(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity + layout.BlockNDataCapacity + 1; // 2 blocks + 1 byte
        var data = MakeData(size);
        var path = GetTestFilePath($"b0bnp1_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_Block0Plus2BlockN(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity + 2 * layout.BlockNDataCapacity; // 3 blocks
        var data = MakeData(size);
        var path = GetTestFilePath($"b0_2bn_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void RoundTrip_Block0Plus10BlockN(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity + 10 * layout.BlockNDataCapacity; // 11 blocks
        var data = MakeData(size);
        var path = GetTestFilePath($"b0_10bn_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    // ═══════════════════════════════════════════════════════════════════
    // 2. Access Pattern Cross-Combinations
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WriteSequential_ReadSequential(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"ss_{blockSize}.enc");
        var data = MakeData(50_000);
        var seqOpts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, seqOpts))
        {
            s.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, seqOpts))
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
    public void WriteSequential_ReadRandomAccess(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"sr_{blockSize}.enc");
        var data = MakeData(50_000);
        var seqOpts = SeqOptions(blockSize);
        var raOpts = RaOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, seqOpts))
        {
            s.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, raOpts))
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
    public void WriteRandomAccess_ReadSequential(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"rs_{blockSize}.enc");
        var data = MakeData(50_000);
        var raOpts = RaOptions(blockSize);
        var seqOpts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, raOpts))
        {
            s.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, seqOpts))
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
    public void WriteRandomAccess_ReadRandomAccess(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"rr_{blockSize}.enc");
        var data = MakeData(50_000);
        var raOpts = RaOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, raOpts))
        {
            s.Write(data, 0, data.Length);
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, raOpts))
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

    // ═══════════════════════════════════════════════════════════════════
    // 3. Buffer Size Variations
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void SmallBufferSize(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int bufferSize = 2 * layout.BlockSize; // minimal ring
        var data = MakeData(100_000);
        var path = GetTestFilePath($"smallbuf_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize, bufferSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void LargeBufferSize(BlockSizeOption blockSize)
    {
        int bufferSize = 4 * 1024 * 1024; // 4 MB
        var data = MakeData(100_000);
        var path = GetTestFilePath($"largebuf_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize, bufferSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void DefaultBufferSize(BlockSizeOption blockSize)
    {
        int bufferSize = 0; // default 1 MB
        var data = MakeData(100_000);
        var path = GetTestFilePath($"defbuf_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize, bufferSize);
        readBack.Should().BeEquivalentTo(data);
    }

    // ═══════════════════════════════════════════════════════════════════
    // 4. Sequential Write Edge Cases
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ChunkedSequentialWrite(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"chunked_{blockSize}.enc");
        var data = MakeData(50_000);
        var opts = SeqOptions(blockSize);

        // Write in 1 KB chunks
        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            int offset = 0;
            while (offset < data.Length)
            {
                int chunk = Math.Min(1024, data.Length - offset);
                s.Write(data, offset, chunk);
                offset += chunk;
            }
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
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
    public void SingleByteWrites(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"singlebyte_{blockSize}.enc");
        var data = MakeData(100); // first 100 bytes
        var opts = SeqOptions(blockSize);

        // Write byte by byte
        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            for (int i = 0; i < data.Length; i++)
            {
                s.WriteByte(data[i]);
            }
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(100);
            for (int i = 0; i < data.Length; i++)
            {
                s.ReadByte().Should().Be(data[i], $"byte at index {i} should match");
            }
            s.ReadByte().Should().Be(-1); // EOF
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ExactSlotBoundaryWrite(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        // Write exactly N * PayloadCapacity bytes which aligns precisely to slot boundaries
        int size = 3 * layout.PayloadCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"slotboundary_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void LargeSequentialWrite_512KB(BlockSizeOption blockSize)
    {
        var data = MakeData(512 * 1024); // 512 KB
        var path = GetTestFilePath($"large512k_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    // ═══════════════════════════════════════════════════════════════════
    // 5. Auto-Fallback
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void SequentialWriteThenSeekBack_FallsBackToBlockManager(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"fallback_seek_{blockSize}.enc");
        var opts = SeqOptions(blockSize);
        var data = MakeData(10_000);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            // Write 10 KB sequentially
            s.Write(data, 0, data.Length);

            // Seek back (triggers fallback to BlockManager)
            s.Seek(0, SeekOrigin.Begin);

            // Write additional data at start
            var overwrite = MakeData(100, seed: 99);
            s.Write(overwrite, 0, overwrite.Length);
        }

        // Verify: first 100 bytes are the overwrite, rest is original
        var expected = new byte[10_000];
        Array.Copy(data, expected, data.Length);
        Array.Copy(MakeData(100, seed: 99), 0, expected, 0, 100);

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(10_000);
            var readBack = new byte[10_000];
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(10_000);
            readBack.Should().BeEquivalentTo(expected);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void OverwriteExistingData_FallsBackToBlockManager(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"fallback_overwrite_{blockSize}.enc");
        var opts = SeqOptions(blockSize);
        var originalData = MakeData(5_000, seed: 10);

        // Create file with initial data
        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(originalData, 0, originalData.Length);
        }

        // Open existing and write at position 0 (triggers fallback)
        var overwrite = MakeData(200, seed: 20);
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, opts))
        {
            s.Write(overwrite, 0, overwrite.Length);
        }

        // Verify: first 200 bytes are overwrite, rest is original
        var expected = new byte[5_000];
        Array.Copy(originalData, expected, originalData.Length);
        Array.Copy(overwrite, 0, expected, 0, overwrite.Length);

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(5_000);
            var readBack = new byte[5_000];
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(5_000);
            readBack.Should().BeEquivalentTo(expected);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void SetLength_FallsBackToBlockManager(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"fallback_setlen_{blockSize}.enc");
        var opts = SeqOptions(blockSize);
        var data = MakeData(10_000);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
            s.SetLength(5000); // triggers fallback
            s.Length.Should().Be(5000);
        }

        // Verify the first 5000 bytes survived
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(5000);
            var readBack = new byte[5000];
            int totalRead = 0;
            while (totalRead < 5000)
            {
                int r = s.Read(readBack, totalRead, 5000 - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(5000);
            readBack.Should().BeEquivalentTo(data.AsSpan(0, 5000).ToArray());
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // 6. Physical File Size
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void PhysicalFileSize_IsMultipleOfBlockSize(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        var path = GetTestFilePath($"physsize_{blockSize}.enc");
        var data = MakeData(10_000);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        var fileInfo = new FileInfo(path);
        fileInfo.Exists.Should().BeTrue();
        (fileInfo.Length % layout.BlockSize).Should().Be(0,
            $"physical file size {fileInfo.Length} should be a multiple of block size {layout.BlockSize}");
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void PhysicalFileSize_EmptyFile_IsOneBlock(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        var path = GetTestFilePath($"physempty_{blockSize}.enc");
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            // Write nothing — empty files still have block 0
        }

        var fileInfo = new FileInfo(path);
        fileInfo.Exists.Should().BeTrue();
        fileInfo.Length.Should().Be(layout.BlockSize,
            "even an empty encrypted file should have exactly one block (block 0)");
    }

    // ═══════════════════════════════════════════════════════════════════
    // 7. Buffer Fill Boundaries
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ReadFill_FileSmallerThanBuffer(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = 2 * layout.BlockNDataCapacity; // well under default 1 MB buffer
        var data = MakeData(size);
        var path = GetTestFilePath($"rfSmaller_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ReadFill_FileExactlyFillsBuffer(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int defaultBuffer = 1024 * 1024;
        int slots = defaultBuffer / layout.BlockSize;
        // Total user data that exactly fills one buffer: block 0 + (slots-1) blockN
        int size = layout.Block0DataCapacity + (slots - 1) * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"rfExact_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ReadFill_FileOneByteMoreThanBuffer(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int defaultBuffer = 1024 * 1024;
        int slots = defaultBuffer / layout.BlockSize;
        int size = layout.Block0DataCapacity + (slots - 1) * layout.BlockNDataCapacity + 1;
        var data = MakeData(size);
        var path = GetTestFilePath($"rfOnePlus_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ReadFill_FileExactlyTwoFills(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int defaultBuffer = 1024 * 1024;
        int slots = defaultBuffer / layout.BlockSize;
        int oneFillData = layout.Block0DataCapacity + (slots - 1) * layout.BlockNDataCapacity;
        // Two fills: first fill covers block 0..(slots-1), second fill covers next 'slots' blocks
        int size = oneFillData + slots * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"rfTwoFills_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WriteFill_DataSmallerThanBuffer(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int defaultBuffer = 1024 * 1024;
        int slots = defaultBuffer / layout.BlockSize;
        int halfCapacity = (layout.Block0DataCapacity + (slots - 1) * layout.BlockNDataCapacity) / 2;
        var data = MakeData(halfCapacity);
        var path = GetTestFilePath($"wfSmaller_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WriteFill_DataExactlyFillsBuffer(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int defaultBuffer = 1024 * 1024;
        int slots = defaultBuffer / layout.BlockSize;
        int size = layout.Block0DataCapacity + (slots - 1) * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"wfExact_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WriteFill_DataOneByteMoreThanBuffer(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int defaultBuffer = 1024 * 1024;
        int slots = defaultBuffer / layout.BlockSize;
        int size = layout.Block0DataCapacity + (slots - 1) * layout.BlockNDataCapacity + 1;
        var data = MakeData(size);
        var path = GetTestFilePath($"wfOnePlus_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void MinimumBufferTwoSlots_ReadWrite(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int bufferSize = 2 * layout.BlockSize;
        var data = MakeData(10 * 1024);
        var path = GetTestFilePath($"minBuf2_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize, bufferSize);
        readBack.Should().BeEquivalentTo(data);
    }

    // ═══════════════════════════════════════════════════════════════════
    // 8. Read Edge Cases
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_OneByteAtATime(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"readOneByte_{blockSize}.enc");
        var data = MakeData(500);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            for (int i = 0; i < data.Length; i++)
            {
                int b = s.ReadByte();
                b.Should().Be(data[i], $"byte at index {i} should match");
            }
            s.ReadByte().Should().Be(-1, "should return -1 at EOF");
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_ExactlyOneBlockPerCall(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int totalBlocks = 5;
        int size = layout.Block0DataCapacity + (totalBlocks - 1) * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"readOneBlock_{blockSize}.enc");
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            var readBack = new byte[size];
            int offset = 0;
            // Read exactly PayloadCapacity per call
            while (offset < size)
            {
                int toRead = Math.Min(layout.PayloadCapacity, size - offset);
                int r = s.Read(readBack, offset, toRead);
                r.Should().BeGreaterThan(0, "should read some data before EOF");
                offset += r;
            }
            readBack.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_LargerThanEntireBuffer(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int bufferSize = 2 * layout.BlockSize;
        int size = 10 * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"readLarger_{blockSize}.enc");
        var opts = SeqOptions(blockSize, bufferSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        var readBack = new byte[size];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            // Single Read request larger than the entire buffer
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(size);
        }
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_CrossingSlotBoundary(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        // Data spanning at least 3 blocks
        int size = layout.Block0DataCapacity + 2 * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"readCross_{blockSize}.enc");
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            // Read across the block 0 / block 1 boundary
            int crossOffset = layout.Block0DataCapacity - 10;
            var buf = new byte[crossOffset];
            int r = s.Read(buf, 0, crossOffset);
            r.Should().BeGreaterThan(0);

            // Now read 20 bytes crossing the boundary
            var crossBuf = new byte[20];
            int crossRead = 0;
            while (crossRead < crossBuf.Length)
            {
                int cr = s.Read(crossBuf, crossRead, crossBuf.Length - crossRead);
                if (cr == 0) break;
                crossRead += cr;
            }
            crossRead.Should().Be(20);
            crossBuf.Should().BeEquivalentTo(data.AsSpan(crossOffset, 20).ToArray());
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_AtEOF_ReturnsZero(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"readEof_{blockSize}.enc");
        var data = MakeData(100);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Seek(0, SeekOrigin.End);
            var buf = new byte[10];
            s.Read(buf, 0, buf.Length).Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_PartialAtEOF(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"readPartialEof_{blockSize}.enc");
        var data = MakeData(200);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Seek(-50, SeekOrigin.End); // Position = Length - 50
            var buf = new byte[100];
            int totalRead = 0;
            while (totalRead < buf.Length)
            {
                int r = s.Read(buf, totalRead, buf.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(50, "only 50 bytes remain before EOF");
            buf.AsSpan(0, 50).ToArray().Should().BeEquivalentTo(data.AsSpan(150, 50).ToArray());
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Read_ZeroCount_ReturnsZero(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"readZero_{blockSize}.enc");
        var data = MakeData(100);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            var buf = new byte[10];
            s.Read(buf, 0, 0).Should().Be(0);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // 9. Write Edge Cases
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_OneByteAtATime_500Bytes(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"writeOneByte_{blockSize}.enc");
        var data = MakeData(500);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            for (int i = 0; i < data.Length; i++)
            {
                s.WriteByte(data[i]);
            }
        }

        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(500);
        }
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_ExactlyOneSlotPerCall(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int totalBlocks = 5;
        int size = layout.Block0DataCapacity + (totalBlocks - 1) * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"writeOneSlot_{blockSize}.enc");
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            int offset = 0;
            while (offset < size)
            {
                int toWrite = Math.Min(layout.PayloadCapacity, size - offset);
                s.Write(data, offset, toWrite);
                offset += toWrite;
            }
        }

        var readBack = new byte[size];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(size);
        }
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_LargerThanBuffer_SingleCall(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int bufferSize = 2 * layout.BlockSize;
        int size = 10 * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"writeLarger_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize, bufferSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_CrossingSlotBoundary(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity + 2 * layout.BlockNDataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"writeCross_{blockSize}.enc");
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            // Write a chunk that crosses the block 0 / block 1 boundary
            int firstWrite = layout.Block0DataCapacity - 10;
            s.Write(data, 0, firstWrite);
            // This 20-byte write crosses the slot boundary
            s.Write(data, firstWrite, 20);
            // Write the rest
            s.Write(data, firstWrite + 20, size - firstWrite - 20);
        }

        var readBack = new byte[size];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(size);
        }
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_AtEOF_Extends(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"writeEof_{blockSize}.enc");
        var data1 = MakeData(500, seed: 1);
        var data2 = MakeData(300, seed: 2);
        var opts = RaOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data1, 0, data1.Length);
        }

        // Reopen and write at EOF
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, opts))
        {
            s.Seek(0, SeekOrigin.End);
            s.Write(data2, 0, data2.Length);
        }

        var expected = new byte[800];
        Array.Copy(data1, 0, expected, 0, 500);
        Array.Copy(data2, 0, expected, 500, 300);

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(800);
            var readBack = new byte[800];
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(800);
            readBack.Should().BeEquivalentTo(expected);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Write_FlushDispose_Persists(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"writeFlush_{blockSize}.enc");
        var data = MakeData(5_000);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
            // Dispose flushes implicitly
        }

        // Reopen and verify data persisted
        var readBack = new byte[data.Length];
        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(data.Length);
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

    // ═══════════════════════════════════════════════════════════════════
    // 10. Block 0 Specific
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Block0_DataFitsEntirely(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"b0fits_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Block0_ExactCapacity(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity;
        var data = MakeData(size);
        var path = GetTestFilePath($"b0exact2_{blockSize}.enc");
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            s.Length.Should().Be(size);
            var readBack = new byte[size];
            int totalRead = 0;
            while (totalRead < readBack.Length)
            {
                int r = s.Read(readBack, totalRead, readBack.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(size);
            readBack.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Block0_CrossesIntoBlock1(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        int size = layout.Block0DataCapacity + 100;
        var data = MakeData(size);
        var path = GetTestFilePath($"b0cross_{blockSize}.enc");

        var readBack = WriteAndReadBack(path, data, blockSize);
        readBack.Should().BeEquivalentTo(data);

        // Verify two physical blocks were written
        var fileInfo = new FileInfo(path);
        fileInfo.Length.Should().Be(2 * layout.BlockSize,
            "data exceeding block 0 capacity should spill into block 1");
    }

    // ═══════════════════════════════════════════════════════════════════
    // 11. Seek Interaction
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Seek_WithinBufferedRange(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"seekWithin_{blockSize}.enc");
        var data = MakeData(50 * 1024);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            // Read first 1 KB to populate the read-ahead buffer
            var buf1 = new byte[1024];
            int r1 = s.Read(buf1, 0, buf1.Length);
            r1.Should().BeGreaterThan(0);

            // Seek backward within the buffered range
            s.Seek(0, SeekOrigin.Begin);

            // Read the same 1 KB again
            var buf2 = new byte[1024];
            int r2 = s.Read(buf2, 0, buf2.Length);
            r2.Should().Be(r1);
            buf2.Should().BeEquivalentTo(buf1);
            buf2.AsSpan(0, r2).ToArray().Should().BeEquivalentTo(data.AsSpan(0, r2).ToArray());
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Seek_OutsideBufferedRange(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"seekOutside_{blockSize}.enc");
        int size = 200 * 1024;
        var data = MakeData(size);
        var opts = SeqOptions(blockSize);

        using (var s = _factory.Create(path, FileMode.Create, opts))
        {
            s.Write(data, 0, data.Length);
        }

        using (var s = _factory.Create(path, FileMode.Open, FileAccess.Read, opts))
        {
            // Read first 1 KB
            var buf1 = new byte[1024];
            int r1 = s.Read(buf1, 0, buf1.Length);
            r1.Should().BeGreaterThan(0);
            buf1.AsSpan(0, r1).ToArray().Should().BeEquivalentTo(data.AsSpan(0, r1).ToArray());

            // Seek to the last 1 KB (likely outside the buffered range, triggers new fill)
            int seekPos = size - 1024;
            s.Seek(seekPos, SeekOrigin.Begin);

            var buf2 = new byte[1024];
            int totalRead = 0;
            while (totalRead < buf2.Length)
            {
                int r = s.Read(buf2, totalRead, buf2.Length - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            totalRead.Should().Be(1024);
            buf2.Should().BeEquivalentTo(data.AsSpan(seekPos, 1024).ToArray());
        }
    }
}
