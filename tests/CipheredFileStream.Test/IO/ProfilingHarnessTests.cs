using System.Diagnostics;
using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;
using Xunit.Abstractions;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Sustained workloads designed for profiler attachment.
/// Run these tests, then attach a profiler (dotMemory, dotTrace, PerfView, etc.)
/// to capture steady-state behavior under load.
/// </summary>
public class ProfilingHarnessTests : CryptoTestBase
{
    private readonly ITestOutputHelper _output;

    public ProfilingHarnessTests(ITestOutputHelper output) : base()
    {
        _output = output;
    }

    [Trait("Category", "Profiling")]
    [Fact]
    public void SustainedSequentialRead_16K_30Seconds()
    {
        const int fileSizeMB = 256;
        const int fileSize = fileSizeMB * 1024 * 1024;
        const int durationSeconds = 30;
        const int readBufferSize = 64 * 1024;

        var options = new CipheredFileStreamOptions
        {
            BlockSize = BlockSizeOption.Block16K,
            AccessPattern = AccessPattern.Sequential,
        };

        var path = GetTestFilePath("profiling_seq_256mb.enc");

        _output.WriteLine($"Creating {fileSizeMB}MB test file with 16K blocks (Sequential)...");
        _output.WriteLine($"Attach profiler now. PID: {Environment.ProcessId}");
        _output.WriteLine($"  dotTrace: dotTrace attach {Environment.ProcessId}");
        _output.WriteLine($"  dotMemory: dotMemory attach {Environment.ProcessId}");

        // Create the file
        var createSw = Stopwatch.StartNew();
        var writeData = new byte[readBufferSize];
        Random.Shared.NextBytes(writeData);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            long written = 0;
            while (written < fileSize)
            {
                int toWrite = (int)Math.Min(readBufferSize, fileSize - written);
                stream.Write(writeData, 0, toWrite);
                written += toWrite;
            }
        }
        createSw.Stop();
        _output.WriteLine($"File created in {createSw.Elapsed.TotalSeconds:F1}s ({fileSizeMB / createSw.Elapsed.TotalSeconds:F1} MB/s write)");

        // Sustained sequential reads for 30 seconds
        var readBuffer = new byte[readBufferSize];
        long iterations = 0;
        long totalBytesRead = 0;

        var sw = Stopwatch.StartNew();
        var deadline = TimeSpan.FromSeconds(durationSeconds);

        while (sw.Elapsed < deadline)
        {
            using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
            int read;
            while ((read = stream.Read(readBuffer, 0, readBuffer.Length)) > 0)
            {
                totalBytesRead += read;
                if (sw.Elapsed >= deadline) break;
            }
            iterations++;
        }

        sw.Stop();

        double totalGB = totalBytesRead / (1024.0 * 1024.0 * 1024.0);
        double avgMBps = totalBytesRead / sw.Elapsed.TotalSeconds / (1024.0 * 1024.0);

        _output.WriteLine($"--- Sequential Read Results ---");
        _output.WriteLine($"Duration: {sw.Elapsed.TotalSeconds:F1}s");
        _output.WriteLine($"Iterations (full file reads): {iterations}");
        _output.WriteLine($"Total read: {totalGB:F2} GB");
        _output.WriteLine($"Avg throughput: {avgMBps:F1} MB/s");

        totalBytesRead.Should().BeGreaterThan(0, "at least some data should have been read");
    }

    [Trait("Category", "Profiling")]
    [Fact]
    public void SustainedRandomRead_16K_30Seconds()
    {
        const int fileSizeMB = 64;
        const int fileSize = fileSizeMB * 1024 * 1024;
        const int durationSeconds = 30;
        const int readChunkSize = 4096;

        var options = new CipheredFileStreamOptions
        {
            BlockSize = BlockSizeOption.Block16K,
            AccessPattern = AccessPattern.RandomAccess,
        };

        var path = GetTestFilePath("profiling_rnd_64mb.enc");

        _output.WriteLine($"Creating {fileSizeMB}MB test file with 16K blocks (RandomAccess)...");
        _output.WriteLine($"Attach profiler now. PID: {Environment.ProcessId}");
        _output.WriteLine($"  dotTrace: dotTrace attach {Environment.ProcessId}");
        _output.WriteLine($"  dotMemory: dotMemory attach {Environment.ProcessId}");

        // Create the file
        var createSw = Stopwatch.StartNew();
        var writeBuffer = new byte[64 * 1024];
        Random.Shared.NextBytes(writeBuffer);

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            long written = 0;
            while (written < fileSize)
            {
                int toWrite = (int)Math.Min(writeBuffer.Length, fileSize - written);
                stream.Write(writeBuffer, 0, toWrite);
                written += toWrite;
            }
        }
        createSw.Stop();
        _output.WriteLine($"File created in {createSw.Elapsed.TotalSeconds:F1}s ({fileSizeMB / createSw.Elapsed.TotalSeconds:F1} MB/s write)");

        // Sustained random 4K reads for 30 seconds
        var readBuffer = new byte[readChunkSize];
        var rng = new Random(42);
        long iterations = 0;
        long totalBytesRead = 0;
        int maxPosition = fileSize - readChunkSize;

        var sw = Stopwatch.StartNew();
        var deadline = TimeSpan.FromSeconds(durationSeconds);

        using (var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            while (sw.Elapsed < deadline)
            {
                int position = rng.Next(0, maxPosition);
                stream.Position = position;

                int read = 0;
                while (read < readChunkSize)
                {
                    int r = stream.Read(readBuffer, read, readChunkSize - read);
                    if (r == 0) break;
                    read += r;
                }

                totalBytesRead += read;
                iterations++;
            }
        }

        sw.Stop();

        double totalGB = totalBytesRead / (1024.0 * 1024.0 * 1024.0);
        double avgMBps = totalBytesRead / sw.Elapsed.TotalSeconds / (1024.0 * 1024.0);

        _output.WriteLine($"--- Random Read Results ---");
        _output.WriteLine($"Duration: {sw.Elapsed.TotalSeconds:F1}s");
        _output.WriteLine($"Random 4K read iterations: {iterations}");
        _output.WriteLine($"Total read: {totalGB:F2} GB");
        _output.WriteLine($"Avg throughput: {avgMBps:F1} MB/s");
        _output.WriteLine($"Avg IOPS: {iterations / sw.Elapsed.TotalSeconds:F0}");

        totalBytesRead.Should().BeGreaterThan(0, "at least some data should have been read");
    }
}
