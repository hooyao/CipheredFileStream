using System.Security.Cryptography;
using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// FileStream parity tests: every operation is mirrored on CipheredFileStream and plain FileStream.
/// After the sequence completes, both files are reopened with NEW instances and compared via SHA-256.
/// This guarantees CipheredFileStream behaves identically to FileStream for any operation sequence.
/// </summary>
public class OperationSequenceParityTests : CryptoTestBase
{
    private const int GcmOverhead = 28;

    private static BlockLayout GetLayout(BlockSizeOption blockSize)
        => new((int)blockSize, GcmOverhead);

    private static byte[] Pattern(int size)
    {
        var d = new byte[size];
        for (int i = 0; i < size; i++) d[i] = (byte)(i % 251);
        return d;
    }

    private static byte[] Fill(int size, byte value)
    {
        var d = new byte[size];
        Array.Fill(d, value);
        return d;
    }

    private void VerifyParity(string cfsPath, string fsPath, CipheredFileStreamOptions options)
    {
        byte[] cfsHash, fsHash;
        long cfsLen, fsLen;

        using (var cfs = _factory.Create(cfsPath, FileMode.Open, FileAccess.Read, options))
        {
            cfsLen = cfs.Length;
            var content = new byte[cfsLen];
            int total = 0;
            while (total < content.Length)
            {
                int r = cfs.Read(content, total, content.Length - total);
                if (r == 0) break;
                total += r;
            }
            total.Should().Be(content.Length);
            cfsHash = SHA256.HashData(content);
        }

        var fsContent = File.ReadAllBytes(fsPath);
        fsLen = fsContent.Length;
        fsHash = SHA256.HashData(fsContent);

        cfsLen.Should().Be(fsLen, "CipheredFileStream and FileStream must have same length");
        cfsHash.Should().BeEquivalentTo(fsHash,
            "CipheredFileStream must produce identical data to FileStream");
    }

    private static void MirrorRead(Stream cfs, Stream fs, int count)
    {
        var cfsBuf = new byte[count];
        var fsBuf = new byte[count];
        int cfsRead = ReadFully(cfs, cfsBuf, count);
        int fsRead = ReadFully(fs, fsBuf, count);
        cfsRead.Should().Be(fsRead, "read count must match");
        cfsBuf.AsSpan(0, cfsRead).ToArray()
            .Should().BeEquivalentTo(fsBuf.AsSpan(0, fsRead).ToArray(), "read data must match");
    }

    private static int ReadFully(Stream s, byte[] buf, int count)
    {
        int total = 0;
        while (total < count)
        {
            int r = s.Read(buf, total, count - total);
            if (r == 0) break;
            total += r;
        }
        return total;
    }

    // ═══════════════════════════════════════════════════════
    // Write + Flush combinations
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity01_Write_Flush_Write_Flush(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p01_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p01_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var part1 = Pattern(500);
            cfs.Write(part1, 0, part1.Length);
            fs.Write(part1, 0, part1.Length);

            cfs.Flush();
            fs.Flush();

            var part2 = Fill(500, 0xBB);
            cfs.Write(part2, 0, part2.Length);
            fs.Write(part2, 0, part2.Length);

            cfs.Flush();
            fs.Flush();
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity02_Write_BlockBoundary_Flush_Write(BlockSizeOption blockSize)
    {
        var layout = GetLayout(blockSize);
        var cfsPath = GetTestFilePath($"p02_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p02_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var part1 = Pattern(layout.Block0DataCapacity);
            cfs.Write(part1, 0, part1.Length);
            fs.Write(part1, 0, part1.Length);

            cfs.Flush();
            fs.Flush();

            var part2 = Fill(500, 0xAA);
            cfs.Write(part2, 0, part2.Length);
            fs.Write(part2, 0, part2.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity03_ThreeFlushCycles(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p03_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p03_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            for (int round = 0; round < 3; round++)
            {
                var chunk = Fill(500, (byte)(0xA0 + round));
                cfs.Write(chunk, 0, chunk.Length);
                fs.Write(chunk, 0, chunk.Length);
                cfs.Flush();
                fs.Flush();
            }
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity04_Write_Flush_Truncate_Append(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p04_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p04_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Flush();
            fs.Flush();

            cfs.SetLength(3000);
            fs.SetLength(3000);

            cfs.Seek(0, SeekOrigin.End);
            fs.Seek(0, SeekOrigin.End);

            var more = Fill(2000, 0xCC);
            cfs.Write(more, 0, more.Length);
            fs.Write(more, 0, more.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    // ═══════════════════════════════════════════════════════
    // Write + Seek + Read (same stream)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity05_Write_Seek_Read_NoFlush(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p05_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p05_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Seek(0, SeekOrigin.Begin);
            fs.Seek(0, SeekOrigin.Begin);

            MirrorRead(cfs, fs, 10_000);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity06_Write_Flush_Seek_Read(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p06_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p06_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Flush();
            fs.Flush();

            cfs.Seek(0, SeekOrigin.Begin);
            fs.Seek(0, SeekOrigin.Begin);

            MirrorRead(cfs, fs, 10_000);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity07_Write_SeekMiddle_Read(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p07_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p07_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Seek(5000, SeekOrigin.Begin);
            fs.Seek(5000, SeekOrigin.Begin);

            MirrorRead(cfs, fs, 100);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity08_Write_MultiSeek_MultiRead(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p08_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p08_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(50_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Seek(0, SeekOrigin.Begin);
            fs.Seek(0, SeekOrigin.Begin);
            MirrorRead(cfs, fs, 1000);

            cfs.Seek(40000, SeekOrigin.Begin);
            fs.Seek(40000, SeekOrigin.Begin);
            MirrorRead(cfs, fs, 1000);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    // ═══════════════════════════════════════════════════════
    // Write + Seek + Write (overwrite and append)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity09_Write_Flush_SeekBegin_Overwrite(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p09_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p09_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Flush();
            fs.Flush();

            cfs.Seek(0, SeekOrigin.Begin);
            fs.Seek(0, SeekOrigin.Begin);

            var patch = Fill(100, 0xAA);
            cfs.Write(patch, 0, patch.Length);
            fs.Write(patch, 0, patch.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity10_Write_Flush_SeekEnd_Append(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p10_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p10_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Flush();
            fs.Flush();

            cfs.Seek(0, SeekOrigin.End);
            fs.Seek(0, SeekOrigin.End);

            var more = Fill(5000, 0xBB);
            cfs.Write(more, 0, more.Length);
            fs.Write(more, 0, more.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity11_Write_Flush_OverwriteMiddle_Append(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p11_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p11_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(5000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Flush();
            fs.Flush();

            cfs.Seek(2000, SeekOrigin.Begin);
            fs.Seek(2000, SeekOrigin.Begin);

            var patch = Fill(100, 0xBB);
            cfs.Write(patch, 0, patch.Length);
            fs.Write(patch, 0, patch.Length);

            cfs.Seek(0, SeekOrigin.End);
            fs.Seek(0, SeekOrigin.End);

            var more = Pattern(3000);
            cfs.Write(more, 0, more.Length);
            fs.Write(more, 0, more.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity12_Write_SeekBegin_OverwriteNoFlush(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p12_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p12_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            // No flush — overwrite with unflushed data in buffer
            cfs.Seek(0, SeekOrigin.Begin);
            fs.Seek(0, SeekOrigin.Begin);

            var patch = Fill(100, 0xCC);
            cfs.Write(patch, 0, patch.Length);
            fs.Write(patch, 0, patch.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    // ═══════════════════════════════════════════════════════
    // Read + Seek + Write (existing file)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity13_ReadExisting_Seek_Overwrite(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p13_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p13_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = Pattern(10_000);

        // Create both files
        using (var cfs = _factory.Create(cfsPath, FileMode.Create, options))
            cfs.Write(data, 0, data.Length);
        File.WriteAllBytes(fsPath, data);

        // Reopen both RW, read then overwrite
        using (var cfs = _factory.Create(cfsPath, FileMode.Open, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Open, FileAccess.ReadWrite))
        {
            MirrorRead(cfs, fs, 5000);

            cfs.Seek(2000, SeekOrigin.Begin);
            fs.Seek(2000, SeekOrigin.Begin);

            var patch = Fill(100, 0xDD);
            cfs.Write(patch, 0, patch.Length);
            fs.Write(patch, 0, patch.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity14_ReadAll_ModifyInMemory_WriteBack(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p14_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p14_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = Pattern(10_000);

        // Create both files
        using (var cfs = _factory.Create(cfsPath, FileMode.Create, options))
            cfs.Write(data, 0, data.Length);
        File.WriteAllBytes(fsPath, data);

        // Reopen both, read all, invert, write back
        using (var cfs = _factory.Create(cfsPath, FileMode.Open, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Open, FileAccess.ReadWrite))
        {
            var cfsBuf = new byte[10_000];
            var fsBuf = new byte[10_000];
            ReadFully(cfs, cfsBuf, 10_000);
            ReadFully(fs, fsBuf, 10_000);

            // Invert all bytes
            for (int i = 0; i < 10_000; i++)
            {
                cfsBuf[i] = (byte)~cfsBuf[i];
                fsBuf[i] = (byte)~fsBuf[i];
            }

            cfs.Seek(0, SeekOrigin.Begin);
            fs.Seek(0, SeekOrigin.Begin);

            cfs.Write(cfsBuf, 0, cfsBuf.Length);
            fs.Write(fsBuf, 0, fsBuf.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity15_ComplexMultiHop(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p15_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p15_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var data = Pattern(20_000);

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, options))
            cfs.Write(data, 0, data.Length);
        File.WriteAllBytes(fsPath, data);

        using (var cfs = _factory.Create(cfsPath, FileMode.Open, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Open, FileAccess.ReadWrite))
        {
            MirrorRead(cfs, fs, 10_000);

            cfs.Seek(5000, SeekOrigin.Begin);
            fs.Seek(5000, SeekOrigin.Begin);

            var patch1 = Fill(200, 0xEE);
            cfs.Write(patch1, 0, patch1.Length);
            fs.Write(patch1, 0, patch1.Length);

            cfs.Seek(15000, SeekOrigin.Begin);
            fs.Seek(15000, SeekOrigin.Begin);

            MirrorRead(cfs, fs, 1000);

            cfs.Seek(18000, SeekOrigin.Begin);
            fs.Seek(18000, SeekOrigin.Begin);

            var patch2 = Fill(500, 0xFF);
            cfs.Write(patch2, 0, patch2.Length);
            fs.Write(patch2, 0, patch2.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    // ═══════════════════════════════════════════════════════
    // Position property (set directly)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity16_SetPosition_Overwrite(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p16_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p16_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(1000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Position = 500;
            fs.Position = 500;

            var patch = Fill(100, 0xFF);
            cfs.Write(patch, 0, patch.Length);
            fs.Write(patch, 0, patch.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity17_SetPosition_Read(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p17_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p17_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(1000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Position = 500;
            fs.Position = 500;

            MirrorRead(cfs, fs, 100);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity18_SetPosition_BeyondEOF_GapFill(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p18_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p18_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(1000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Position = 2000;
            fs.Position = 2000;

            var patch = Fill(100, 0xAA);
            cfs.Write(patch, 0, patch.Length);
            fs.Write(patch, 0, patch.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    // ═══════════════════════════════════════════════════════
    // Dispose without explicit Flush
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity19_Write_DisposeNoFlush(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p19_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p19_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);
            // No explicit Flush — Dispose must handle it
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity20_Write_Flush_Write_DisposeNoFlush(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p20_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p20_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.Flush();
            fs.Flush();

            var more = Fill(5000, 0xDD);
            cfs.Write(more, 0, more.Length);
            fs.Write(more, 0, more.Length);
            // No second Flush
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    // ═══════════════════════════════════════════════════════
    // SetLength combinations
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity21_Truncate(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p21_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p21_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.SetLength(5000);
            fs.SetLength(5000);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity22_Extend(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p22_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p22_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(100);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.SetLength(1000);
            fs.SetLength(1000);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity23_Truncate_ThenAppend(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p23_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p23_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.SetLength(5000);
            fs.SetLength(5000);

            cfs.Seek(0, SeekOrigin.End);
            fs.Seek(0, SeekOrigin.End);

            var more = Fill(2000, 0xEE);
            cfs.Write(more, 0, more.Length);
            fs.Write(more, 0, more.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity24_TruncateToZero_Rewrite(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p24_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p24_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var data = Pattern(10_000);
            cfs.Write(data, 0, data.Length);
            fs.Write(data, 0, data.Length);

            cfs.SetLength(0);
            fs.SetLength(0);

            var newData = Fill(5000, 0xAB);
            cfs.Write(newData, 0, newData.Length);
            fs.Write(newData, 0, newData.Length);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    // ═══════════════════════════════════════════════════════
    // Multiple Flush + Seek cycles (stress)
    // ═══════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity25_FlushSeekReadWriteCycle(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p25_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p25_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            var chunk = Pattern(1000);
            cfs.Write(chunk, 0, chunk.Length);
            fs.Write(chunk, 0, chunk.Length);

            cfs.Flush();
            fs.Flush();

            cfs.Seek(0, SeekOrigin.Begin);
            fs.Seek(0, SeekOrigin.Begin);

            MirrorRead(cfs, fs, 1000);

            cfs.Seek(0, SeekOrigin.End);
            fs.Seek(0, SeekOrigin.End);

            var chunk2 = Fill(1000, 0xBB);
            cfs.Write(chunk2, 0, chunk2.Length);
            fs.Write(chunk2, 0, chunk2.Length);

            cfs.Flush();
            fs.Flush();

            cfs.Seek(0, SeekOrigin.Begin);
            fs.Seek(0, SeekOrigin.Begin);

            MirrorRead(cfs, fs, 2000);
        }

        VerifyParity(cfsPath, fsPath, options);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Parity26_RepeatedAppendFlushReadAll(BlockSizeOption blockSize)
    {
        var cfsPath = GetTestFilePath($"p26_cfs_{blockSize}.enc");
        var fsPath = GetTestFilePath($"p26_fs_{blockSize}.bin");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var cfs = _factory.Create(cfsPath, FileMode.Create, FileAccess.ReadWrite, options))
        using (var fs = new FileStream(fsPath, FileMode.Create, FileAccess.ReadWrite))
        {
            for (int round = 0; round < 10; round++)
            {
                var chunk = Fill(500, (byte)(round + 1));
                cfs.Write(chunk, 0, chunk.Length);
                fs.Write(chunk, 0, chunk.Length);

                cfs.Flush();
                fs.Flush();

                int totalSize = (round + 1) * 500;
                cfs.Seek(0, SeekOrigin.Begin);
                fs.Seek(0, SeekOrigin.Begin);

                MirrorRead(cfs, fs, totalSize);

                cfs.Seek(0, SeekOrigin.End);
                fs.Seek(0, SeekOrigin.End);
            }
        }

        VerifyParity(cfsPath, fsPath, options);
    }
}
