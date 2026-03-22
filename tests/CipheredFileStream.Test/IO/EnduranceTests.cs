using System.Diagnostics;
using System.Security.Cryptography;
using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;
using Xunit.Abstractions;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Long-running stress tests that hammer CipheredFileStream with parallel workloads.
/// Uses TortureTestBudget for unified disk budget management.
/// </summary>
[Collection("TortureTests")]
public class EnduranceTests : IDisposable
{
    private readonly TortureTestBudget _budget;
    private readonly ITestOutputHelper _output;
    private readonly string _testDir;
    private readonly byte[] _key;
    private readonly CipheredFileStreamFactory _factory;

    private static readonly BlockSizeOption[] BlockSizeOptions =
    [
        BlockSizeOption.Block4K,
        BlockSizeOption.Block8K,
        BlockSizeOption.Block16K,
        BlockSizeOption.Block32K,
        BlockSizeOption.Block64K,
        BlockSizeOption.Block128K,
    ];

    public EnduranceTests(TortureTestBudget budget, ITestOutputHelper output)
    {
        _budget = budget;
        _output = output;
        _testDir = Path.Combine(budget.TempDir, $"CFS_Endurance_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);

        _key = new byte[EncryptedFileFormat.KeySize];
        Random.Shared.NextBytes(_key);
        _factory = new CipheredFileStreamFactory(_key);
    }

    [Trait("Category", "Endurance")]
    [Fact]
    public void EncryptDecryptVerify_Endurance()
    {
        _output.WriteLine(_budget.FormatSummary());

        long totalIterations = 0;
        long totalBytes = 0;
        long failures = 0;

        var sw = Stopwatch.StartNew();
        var deadline = _budget.Duration;

        var tasks = Enumerable.Range(0, _budget.TaskCount).Select(taskIndex => Task.Run(() =>
        {
            var rng = new Random(taskIndex * 7919 + Environment.TickCount);
            long localIterations = 0;
            long localBytes = 0;
            long localFailures = 0;
            long maxFileSize = _budget.GetMaxFileSizeForTask(taskIndex);

            while (sw.Elapsed < deadline)
            {
                string path = Path.Combine(_testDir, $"endurance_{taskIndex}_{localIterations}.enc");
                try
                {
                    // File size: 1KB to maxFileSize (budget-limited)
                    int fileSize = (int)Math.Min(rng.Next(1024, (int)Math.Min(maxFileSize, 1024 * 1024) + 1), maxFileSize);

                    var data = new byte[fileSize];
                    rng.NextBytes(data);

                    var blockSize = BlockSizeOptions[rng.Next(BlockSizeOptions.Length)];
                    var accessPattern = rng.Next(4) < 3
                        ? AccessPattern.Sequential
                        : AccessPattern.RandomAccess;

                    var options = new CipheredFileStreamOptions
                    {
                        BlockSize = blockSize,
                        AccessPattern = accessPattern,
                    };

                    // Write
                    using (var stream = _factory.Create(path, FileMode.Create, options))
                    {
                        stream.Write(data, 0, data.Length);
                    }

                    // Read back and verify SHA256
                    byte[] expectedHash = SHA256.HashData(data);

                    var readBack = new byte[fileSize];
                    using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
                    {
                        int totalRead = 0;
                        while (totalRead < fileSize)
                        {
                            int read = stream.Read(readBack, totalRead, fileSize - totalRead);
                            if (read == 0) break;
                            totalRead += read;
                        }
                        totalRead.Should().Be(fileSize);
                    }

                    byte[] actualHash = SHA256.HashData(readBack);
                    if (!expectedHash.AsSpan().SequenceEqual(actualHash))
                        Interlocked.Increment(ref localFailures);

                    localBytes += fileSize;
                    localIterations++;
                }
                catch (Exception)
                {
                    Interlocked.Increment(ref localFailures);
                }
                finally
                {
                    try { if (File.Exists(path)) File.Delete(path); } catch { }
                }
            }

            Interlocked.Add(ref totalIterations, localIterations);
            Interlocked.Add(ref totalBytes, localBytes);
            Interlocked.Add(ref failures, localFailures);
        })).ToArray();

        Task.WaitAll(tasks);
        sw.Stop();

        _output.WriteLine($"Completed in {sw.Elapsed.TotalSeconds:F1}s");
        _output.WriteLine($"Total iterations: {totalIterations}");
        _output.WriteLine($"Total bytes: {totalBytes:N0} ({totalBytes / (1024.0 * 1024.0):F1} MB)");
        _output.WriteLine($"Throughput: {totalBytes / sw.Elapsed.TotalSeconds / (1024.0 * 1024.0):F1} MB/s");
        _output.WriteLine($"Failures: {failures}");

        failures.Should().Be(0, "all encrypt/decrypt cycles must produce matching SHA256 hashes");
    }

    [Trait("Category", "Endurance")]
    [Fact]
    public void FileStreamParity_Endurance()
    {
        _output.WriteLine(_budget.FormatSummary());

        long totalOps = 0;
        long mismatches = 0;

        var sw = Stopwatch.StartNew();
        var deadline = _budget.Duration;

        var tasks = Enumerable.Range(0, _budget.TaskCount).Select(taskIndex => Task.Run(() =>
        {
            var rng = new Random(taskIndex * 6271 + Environment.TickCount);
            long localOps = 0;
            long localMismatches = 0;
            long maxFileSize = _budget.GetMaxFileSizeForTask(taskIndex);

            while (sw.Elapsed < deadline)
            {
                string cfsPath = Path.Combine(_testDir, $"parity_cfs_{taskIndex}_{localOps}.enc");
                string plainPath = Path.Combine(_testDir, $"parity_plain_{taskIndex}_{localOps}.bin");

                try
                {
                    int fileSize = (int)Math.Min(rng.Next(1024, (int)Math.Min(maxFileSize, 500 * 1024) + 1), maxFileSize);
                    var data = new byte[fileSize];
                    rng.NextBytes(data);

                    var options = new CipheredFileStreamOptions
                    {
                        BlockSize = BlockSizeOptions[rng.Next(BlockSizeOptions.Length)],
                        AccessPattern = AccessPattern.RandomAccess,
                    };

                    using (var cfs = _factory.Create(cfsPath, FileMode.Create, options))
                    {
                        cfs.Write(data, 0, data.Length);
                    }

                    File.WriteAllBytes(plainPath, data);

                    int operationCount = rng.Next(5, 20);

                    using var cfs2 = _factory.Create(cfsPath, FileMode.Open, FileAccess.ReadWrite, options);
                    using var plain = new FileStream(plainPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

                    for (int op = 0; op < operationCount && sw.Elapsed < deadline; op++)
                    {
                        int opType = rng.Next(2);

                        if (opType == 0)
                        {
                            int maxPos = Math.Max(0, fileSize - 1);
                            int pos = maxPos > 0 ? rng.Next(maxPos) : 0;
                            int readLen = Math.Min(rng.Next(1, 4096), fileSize - pos);

                            var cfsBuf = new byte[readLen];
                            var plainBuf = new byte[readLen];

                            cfs2.Position = pos;
                            int cfsRead = 0;
                            while (cfsRead < readLen)
                            {
                                int r = cfs2.Read(cfsBuf, cfsRead, readLen - cfsRead);
                                if (r == 0) break;
                                cfsRead += r;
                            }

                            plain.Position = pos;
                            int plainRead = 0;
                            while (plainRead < readLen)
                            {
                                int r = plain.Read(plainBuf, plainRead, readLen - plainRead);
                                if (r == 0) break;
                                plainRead += r;
                            }

                            if (cfsRead != plainRead || !cfsBuf.AsSpan(0, cfsRead).SequenceEqual(plainBuf.AsSpan(0, plainRead)))
                                localMismatches++;
                        }
                        else
                        {
                            int maxPos = Math.Max(0, fileSize - 1);
                            int pos = maxPos > 0 ? rng.Next(maxPos) : 0;
                            int writeLen = Math.Min(rng.Next(1, 2048), fileSize - pos);
                            var writeData = new byte[writeLen];
                            rng.NextBytes(writeData);

                            cfs2.Position = pos;
                            cfs2.Write(writeData, 0, writeData.Length);
                            cfs2.Flush();

                            plain.Position = pos;
                            plain.Write(writeData, 0, writeData.Length);
                            plain.Flush();
                        }

                        localOps++;
                    }

                    // Final parity check
                    int currentSize = (int)plain.Length;
                    var cfsFinal = new byte[currentSize];
                    var plainFinal = new byte[currentSize];

                    cfs2.Position = 0;
                    int cfsTotal = 0;
                    while (cfsTotal < currentSize)
                    {
                        int r = cfs2.Read(cfsFinal, cfsTotal, currentSize - cfsTotal);
                        if (r == 0) break;
                        cfsTotal += r;
                    }

                    plain.Position = 0;
                    int plainTotal = 0;
                    while (plainTotal < currentSize)
                    {
                        int r = plain.Read(plainFinal, plainTotal, currentSize - plainTotal);
                        if (r == 0) break;
                        plainTotal += r;
                    }

                    if (cfsTotal != plainTotal || !cfsFinal.AsSpan(0, cfsTotal).SequenceEqual(plainFinal.AsSpan(0, plainTotal)))
                        localMismatches++;

                    localOps++;
                }
                catch (Exception)
                {
                    localMismatches++;
                }
                finally
                {
                    try { if (File.Exists(cfsPath)) File.Delete(cfsPath); } catch { }
                    try { if (File.Exists(plainPath)) File.Delete(plainPath); } catch { }
                }
            }

            Interlocked.Add(ref totalOps, localOps);
            Interlocked.Add(ref mismatches, localMismatches);
        })).ToArray();

        Task.WaitAll(tasks);
        sw.Stop();

        _output.WriteLine($"Completed in {sw.Elapsed.TotalSeconds:F1}s");
        _output.WriteLine($"Total operations: {totalOps}");
        _output.WriteLine($"Mismatches: {mismatches}");

        mismatches.Should().Be(0, "CipheredFileStream must behave identically to plain FileStream");
    }

    public void Dispose()
    {
        _factory.Dispose();
        try
        {
            if (Directory.Exists(_testDir))
                Directory.Delete(_testDir, true);
        }
        catch { }
    }
}
