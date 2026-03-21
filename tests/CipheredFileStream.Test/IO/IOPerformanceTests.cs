using System.Diagnostics;
using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;
using Xunit.Abstractions;

namespace CipheredFileStream.Test.IO;

public class IOPerformanceTests : CryptoTestBase
{
    private readonly ITestOutputHelper _output;

    public IOPerformanceTests(ITestOutputHelper output) : base()
    {
        _output = output;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static (double elapsedMs, double throughputMBps) MeasureThroughput(Action action, long totalBytes)
    {
        var sw = Stopwatch.StartNew();
        action();
        sw.Stop();
        double elapsedMs = sw.Elapsed.TotalMilliseconds;
        double throughputMBps = totalBytes / (1024.0 * 1024.0) / (elapsedMs / 1000.0);
        return (elapsedMs, throughputMBps);
    }

    private void WriteLargeFile(string path, long size, int chunkSize, CipheredFileStreamOptions options)
    {
        var data = new byte[chunkSize];
        Random.Shared.NextBytes(data);

        using var stream = _factory.Create(path, FileMode.Create, options);
        long written = 0;
        while (written < size)
        {
            int toWrite = (int)Math.Min(chunkSize, size - written);
            stream.Write(data, 0, toWrite);
            written += toWrite;
        }
    }

    private void ReadLargeFile(string path, long size, int chunkSize, CipheredFileStreamOptions options)
    {
        var buffer = new byte[chunkSize];

        using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        long totalRead = 0;
        while (totalRead < size)
        {
            int read = stream.Read(buffer, 0, chunkSize);
            if (read == 0) break;
            totalRead += read;
        }
    }

    private static void WriteBaseline(string path, long size, int chunkSize)
    {
        var data = new byte[chunkSize];
        Random.Shared.NextBytes(data);

        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, chunkSize);
        long written = 0;
        while (written < size)
        {
            int toWrite = (int)Math.Min(chunkSize, size - written);
            fs.Write(data, 0, toWrite);
            written += toWrite;
        }
    }

    private static void ReadBaseline(string path, long size, int chunkSize)
    {
        var buffer = new byte[chunkSize];

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, chunkSize);
        long totalRead = 0;
        while (totalRead < size)
        {
            int read = fs.Read(buffer, 0, chunkSize);
            if (read == 0) break;
            totalRead += read;
        }
    }

    // ── Sequential Write ────────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Theory]
    [InlineData(4096)]
    [InlineData(65536)]
    [InlineData(1048576)]
    public void SequentialWrite_256MB(int chunkSize)
    {
        const long fileSize = 256L * 1024 * 1024;
        var options = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };
        string encPath = GetTestFilePath($"seqwrite_{chunkSize}.enc");
        string rawPath = GetTestFilePath($"seqwrite_{chunkSize}.raw");

        var (encMs, encMBps) = MeasureThroughput(
            () => WriteLargeFile(encPath, fileSize, chunkSize, options), fileSize);

        var (rawMs, rawMBps) = MeasureThroughput(
            () => WriteBaseline(rawPath, fileSize, chunkSize), fileSize);

        double overheadPct = ((encMs - rawMs) / rawMs) * 100.0;

        _output.WriteLine($"Sequential Write 256MB (chunk={chunkSize}):");
        _output.WriteLine($"  CipheredFileStream : {encMs:F1} ms, {encMBps:F1} MB/s");
        _output.WriteLine($"  FileStream baseline: {rawMs:F1} ms, {rawMBps:F1} MB/s");
        _output.WriteLine($"  Overhead           : {overheadPct:F1}%");

        encMBps.Should().BeGreaterThan(0, "throughput must be positive");
    }

    // ── Sequential Read ─────────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Theory]
    [InlineData(4096)]
    [InlineData(65536)]
    [InlineData(1048576)]
    public void SequentialRead_256MB(int chunkSize)
    {
        const long fileSize = 256L * 1024 * 1024;
        var options = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };
        string encPath = GetTestFilePath($"seqread_{chunkSize}.enc");

        // Prepare file
        WriteLargeFile(encPath, fileSize, chunkSize, options);

        var (encMs, encMBps) = MeasureThroughput(
            () => ReadLargeFile(encPath, fileSize, chunkSize, options), fileSize);

        _output.WriteLine($"Sequential Read 256MB (chunk={chunkSize}):");
        _output.WriteLine($"  CipheredFileStream : {encMs:F1} ms, {encMBps:F1} MB/s");

        encMBps.Should().BeGreaterThan(0, "throughput must be positive");
    }

    // ── Compare Read Strategies ─────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void CompareReadStrategies_100MB()
    {
        const long fileSize = 100L * 1024 * 1024;
        const int chunkSize = 65536;
        string path = GetTestFilePath("readstrategy.enc");

        var seqOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };
        WriteLargeFile(path, fileSize, chunkSize, seqOptions);

        var (seqMs, seqMBps) = MeasureThroughput(
            () => ReadLargeFile(path, fileSize, chunkSize, seqOptions), fileSize);

        var raOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.RandomAccess };
        var (raMs, raMBps) = MeasureThroughput(
            () => ReadLargeFile(path, fileSize, chunkSize, raOptions), fileSize);

        _output.WriteLine("Compare Read Strategies (100MB, 64K chunks):");
        _output.WriteLine($"  Sequential   : {seqMs:F1} ms, {seqMBps:F1} MB/s");
        _output.WriteLine($"  RandomAccess : {raMs:F1} ms, {raMBps:F1} MB/s");

        seqMBps.Should().BeGreaterThan(0);
        raMBps.Should().BeGreaterThan(0);
    }

    // ── Random 4K Read ──────────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void Random4KRead_10000Ops()
    {
        const long fileSize = 100L * 1024 * 1024;
        const int readSize = 4096;
        const int opCount = 10000;
        string path = GetTestFilePath("rand4kread.enc");

        var seqOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };
        WriteLargeFile(path, fileSize, readSize, seqOptions);

        var raOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.RandomAccess };
        var buffer = new byte[readSize];
        var rng = new Random(42);

        var sw = Stopwatch.StartNew();
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, raOptions))
        {
            long maxPos = stream.Length - readSize;
            for (int i = 0; i < opCount; i++)
            {
                long pos = (long)(rng.NextDouble() * maxPos);
                stream.Seek(pos, SeekOrigin.Begin);
                stream.Read(buffer, 0, readSize);
            }
        }
        sw.Stop();

        double totalMs = sw.Elapsed.TotalMilliseconds;
        double iops = opCount / (totalMs / 1000.0);
        double avgLatencyUs = totalMs / opCount * 1000.0;

        _output.WriteLine($"Random 4K Read ({opCount} ops on 100MB file):");
        _output.WriteLine($"  Total time  : {totalMs:F1} ms");
        _output.WriteLine($"  IOPS        : {iops:F0}");
        _output.WriteLine($"  Avg latency : {avgLatencyUs:F1} us");

        iops.Should().BeGreaterThan(0);
    }

    // ── Random 4K Write ─────────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void Random4KWrite_10000Ops()
    {
        const long fileSize = 100L * 1024 * 1024;
        const int writeSize = 4096;
        const int opCount = 10000;
        string path = GetTestFilePath("rand4kwrite.enc");

        var seqOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };
        WriteLargeFile(path, fileSize, writeSize, seqOptions);

        var raOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.RandomAccess };
        var data = new byte[writeSize];
        Random.Shared.NextBytes(data);
        var rng = new Random(42);

        var sw = Stopwatch.StartNew();
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, raOptions))
        {
            long maxPos = stream.Length - writeSize;
            for (int i = 0; i < opCount; i++)
            {
                long pos = (long)(rng.NextDouble() * maxPos);
                stream.Seek(pos, SeekOrigin.Begin);
                stream.Write(data, 0, writeSize);
            }
        }
        sw.Stop();

        double totalMs = sw.Elapsed.TotalMilliseconds;
        double iops = opCount / (totalMs / 1000.0);

        _output.WriteLine($"Random 4K Write ({opCount} ops on 100MB file):");
        _output.WriteLine($"  Total time : {totalMs:F1} ms");
        _output.WriteLine($"  IOPS       : {iops:F0}");

        iops.Should().BeGreaterThan(0);
    }

    // ── Mixed Random IO ─────────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void MixedRandomIO_70Read30Write()
    {
        const long fileSize = 100L * 1024 * 1024;
        const int ioSize = 4096;
        const int opCount = 10000;
        string path = GetTestFilePath("mixedio.enc");

        var seqOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };
        WriteLargeFile(path, fileSize, ioSize, seqOptions);

        var raOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.RandomAccess };
        var readBuf = new byte[ioSize];
        var writeBuf = new byte[ioSize];
        Random.Shared.NextBytes(writeBuf);
        var rng = new Random(42);

        var sw = Stopwatch.StartNew();
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.ReadWrite, raOptions))
        {
            long maxPos = stream.Length - ioSize;
            for (int i = 0; i < opCount; i++)
            {
                long pos = (long)(rng.NextDouble() * maxPos);
                stream.Seek(pos, SeekOrigin.Begin);

                if (rng.NextDouble() < 0.7)
                    stream.Read(readBuf, 0, ioSize);
                else
                    stream.Write(writeBuf, 0, ioSize);
            }
        }
        sw.Stop();

        double totalMs = sw.Elapsed.TotalMilliseconds;
        double iops = opCount / (totalMs / 1000.0);

        _output.WriteLine($"Mixed Random IO 70/30 ({opCount} ops on 100MB file):");
        _output.WriteLine($"  Total time : {totalMs:F1} ms");
        _output.WriteLine($"  Mixed IOPS : {iops:F0}");

        iops.Should().BeGreaterThan(0);
    }

    // ── Create 1000 Small Files ─────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void Create1000SmallFiles()
    {
        const int fileCount = 1000;
        const int fileSize = 1024;
        var data = GenerateRandomData(fileSize);
        var options = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < fileCount; i++)
        {
            string path = GetTestFilePath($"small_{i:D4}.enc");
            using var stream = _factory.Create(path, FileMode.Create, options);
            stream.Write(data, 0, data.Length);
        }
        sw.Stop();

        double totalMs = sw.Elapsed.TotalMilliseconds;
        double filesPerSec = fileCount / (totalMs / 1000.0);

        _output.WriteLine($"Create {fileCount} x {fileSize}B files:");
        _output.WriteLine($"  Total time  : {totalMs:F1} ms");
        _output.WriteLine($"  Files/sec   : {filesPerSec:F0}");

        filesPerSec.Should().BeGreaterThan(0);
    }

    // ── Many Small Writes ───────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void ManySmallWrites_100000x100Bytes()
    {
        const int writeCount = 100000;
        const int writeSize = 100;
        long totalBytes = (long)writeCount * writeSize;
        string path = GetTestFilePath("manysmall.enc");
        var data = new byte[writeSize];
        Random.Shared.NextBytes(data);
        var options = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };

        var (elapsedMs, throughputMBps) = MeasureThroughput(() =>
        {
            using var stream = _factory.Create(path, FileMode.Create, options);
            for (int i = 0; i < writeCount; i++)
                stream.Write(data, 0, writeSize);
        }, totalBytes);

        _output.WriteLine($"Many Small Writes ({writeCount} x {writeSize}B):");
        _output.WriteLine($"  Total time  : {elapsedMs:F1} ms");
        _output.WriteLine($"  Throughput  : {throughputMBps:F1} MB/s");

        throughputMBps.Should().BeGreaterThan(0);
    }

    // ── Block Thrashing ─────────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void BlockThrashing_AlternatingBlocks()
    {
        const int iterations = 1000;
        string path = GetTestFilePath("thrash.enc");
        var options = new CipheredFileStreamOptions
        {
            BlockSize = BlockSizeOption.Block16K,
            AccessPattern = AccessPattern.RandomAccess
        };

        // Compute block data capacity so we can create a 10-block file
        var layout = new BlockLayout((int)BlockSizeOption.Block16K, 28);
        int block0Data = layout.Block0DataCapacity;
        int blockNData = layout.BlockNDataCapacity;
        long tenBlockSize = block0Data + 9L * blockNData;

        var fillData = GenerateRandomData((int)tenBlockSize);
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(fillData, 0, fillData.Length);
        }

        var buffer = new byte[64];
        long block9Offset = block0Data + 8L * blockNData;

        var sw = Stopwatch.StartNew();
        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            for (int i = 0; i < iterations; i++)
            {
                // Read from block 0
                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(buffer, 0, buffer.Length);

                // Read from block 9
                stream.Seek(block9Offset, SeekOrigin.Begin);
                stream.Read(buffer, 0, buffer.Length);
            }
        }
        sw.Stop();

        double totalMs = sw.Elapsed.TotalMilliseconds;
        double iops = (iterations * 2) / (totalMs / 1000.0);

        _output.WriteLine($"Block Thrashing (alternating block 0 & 9, {iterations} iterations):");
        _output.WriteLine($"  Total time : {totalMs:F1} ms");
        _output.WriteLine($"  IOPS       : {iops:F0}");

        iops.Should().BeGreaterThan(0);
    }

    // ── Sequential Write+Read All Block Sizes ───────────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void SequentialWriteRead_AllBlockSizes_256MB()
    {
        const long fileSize = 256L * 1024 * 1024;
        const int chunkSize = 65536;

        _output.WriteLine("Sequential Write+Read 256MB — All Block Sizes:");
        _output.WriteLine($"  {"BlockSize",-12} {"Write MB/s",12} {"Read MB/s",12}");
        _output.WriteLine($"  {new string('-', 36)}");

        foreach (BlockSizeOption blockSize in Enum.GetValues<BlockSizeOption>())
        {
            string path = GetTestFilePath($"allbs_{blockSize}.enc");
            var options = new CipheredFileStreamOptions
            {
                BlockSize = blockSize,
                AccessPattern = AccessPattern.Sequential
            };

            var (writeMs, writeMBps) = MeasureThroughput(
                () => WriteLargeFile(path, fileSize, chunkSize, options), fileSize);

            var (readMs, readMBps) = MeasureThroughput(
                () => ReadLargeFile(path, fileSize, chunkSize, options), fileSize);

            _output.WriteLine($"  {blockSize,-12} {writeMBps,12:F1} {readMBps,12:F1}");
        }
    }

    // ── Sequential vs Random Access All Block Sizes ─────────────────────────

    [Trait("Category", "Performance")]
    [Fact]
    public void SequentialVsRandomAccess_AllBlockSizes_64MB()
    {
        const long fileSize = 64L * 1024 * 1024;
        const int chunkSize = 65536;

        _output.WriteLine("Sequential vs RandomAccess Read 64MB — All Block Sizes:");
        _output.WriteLine($"  {"BlockSize",-12} {"Seq MB/s",12} {"RA MB/s",12} {"Seq/RA Ratio",14}");
        _output.WriteLine($"  {new string('-', 50)}");

        foreach (BlockSizeOption blockSize in Enum.GetValues<BlockSizeOption>())
        {
            string path = GetTestFilePath($"seqvsra_{blockSize}.enc");
            var seqOptions = new CipheredFileStreamOptions
            {
                BlockSize = blockSize,
                AccessPattern = AccessPattern.Sequential
            };

            WriteLargeFile(path, fileSize, chunkSize, seqOptions);

            var (_, seqMBps) = MeasureThroughput(
                () => ReadLargeFile(path, fileSize, chunkSize, seqOptions), fileSize);

            var raOptions = new CipheredFileStreamOptions
            {
                BlockSize = blockSize,
                AccessPattern = AccessPattern.RandomAccess
            };

            var (_, raMBps) = MeasureThroughput(
                () => ReadLargeFile(path, fileSize, chunkSize, raOptions), fileSize);

            double ratio = raMBps > 0 ? seqMBps / raMBps : 0;
            _output.WriteLine($"  {blockSize,-12} {seqMBps,12:F1} {raMBps,12:F1} {ratio,14:F2}x");
        }
    }

    // ── Concurrency Write ───────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public void ConcurrencyComparison_Write_256MB(int concurrency)
    {
        const long fileSize = 256L * 1024 * 1024;
        const int chunkSize = 65536;
        string path = GetTestFilePath($"concwrite_{concurrency}.enc");

        var options = new CipheredFileStreamOptions
        {
            AccessPattern = AccessPattern.Sequential,
            ConcurrencyLevel = concurrency
        };

        var (elapsedMs, throughputMBps) = MeasureThroughput(
            () => WriteLargeFile(path, fileSize, chunkSize, options), fileSize);

        _output.WriteLine($"Concurrent Write 256MB (concurrency={concurrency}):");
        _output.WriteLine($"  Time       : {elapsedMs:F1} ms");
        _output.WriteLine($"  Throughput : {throughputMBps:F1} MB/s");

        throughputMBps.Should().BeGreaterThan(0);
    }

    // ── Concurrency Read ────────────────────────────────────────────────────

    [Trait("Category", "Performance")]
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public void ConcurrencyComparison_Read_256MB(int concurrency)
    {
        const long fileSize = 256L * 1024 * 1024;
        const int chunkSize = 65536;
        string path = GetTestFilePath($"concread_{concurrency}.enc");

        // Prepare file with default concurrency
        var writeOptions = new CipheredFileStreamOptions { AccessPattern = AccessPattern.Sequential };
        WriteLargeFile(path, fileSize, chunkSize, writeOptions);

        var readOptions = new CipheredFileStreamOptions
        {
            AccessPattern = AccessPattern.Sequential,
            ConcurrencyLevel = concurrency
        };

        var (elapsedMs, throughputMBps) = MeasureThroughput(
            () => ReadLargeFile(path, fileSize, chunkSize, readOptions), fileSize);

        _output.WriteLine($"Concurrent Read 256MB (concurrency={concurrency}):");
        _output.WriteLine($"  Time       : {elapsedMs:F1} ms");
        _output.WriteLine($"  Throughput : {throughputMBps:F1} MB/s");

        throughputMBps.Should().BeGreaterThan(0);
    }
}
