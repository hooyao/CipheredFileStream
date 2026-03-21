using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Parallel crypto tests, workflow scenarios, and block size header verification.
/// </summary>
public class ParallelCryptoAndWorkflowTests : CryptoTestBase
{
    private const int GcmOverhead = 28;

    private static CipheredFileStreamOptions MakeOptions(
        BlockSizeOption blockSize = BlockSizeOption.Block16K,
        int concurrency = 0,
        AccessPattern access = AccessPattern.Sequential) => new()
    {
        BlockSize = blockSize,
        ConcurrencyLevel = concurrency,
        AccessPattern = access,
    };

    private void WriteFile(string path, byte[] data, CipheredFileStreamOptions options)
    {
        using var stream = _factory.Create(path, FileMode.Create, options);
        if (data.Length > 0)
            stream.Write(data, 0, data.Length);
    }

    private byte[] ReadFile(string path, int expectedSize, CipheredFileStreamOptions options)
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
        totalRead.Should().Be(expectedSize, "all bytes should be read back");
        return buffer;
    }

    // ═══════════════════════════════════════════════════════════════════
    // Concurrency equivalence tests
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ConcurrencyEquivalence_Write(BlockSizeOption blockSize)
    {
        const int size = 200 * 1024; // 200KB
        var data = GenerateRandomData(size);

        var pathC1 = GetTestFilePath($"ceq_w_c1_{blockSize}.enc");
        var pathC4 = GetTestFilePath($"ceq_w_c4_{blockSize}.enc");

        WriteFile(pathC1, data, MakeOptions(blockSize, concurrency: 1));
        WriteFile(pathC4, data, MakeOptions(blockSize, concurrency: 4));

        // Read both back with concurrency=1 and compare
        var readC1 = ReadFile(pathC1, size, MakeOptions(blockSize, concurrency: 1));
        var readC4 = ReadFile(pathC4, size, MakeOptions(blockSize, concurrency: 1));

        readC1.Should().Equal(data, "C=1 write must round-trip correctly");
        readC4.Should().Equal(data, "C=4 write must round-trip correctly");
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ConcurrencyEquivalence_Read(BlockSizeOption blockSize)
    {
        const int size = 200 * 1024; // 200KB
        var data = GenerateRandomData(size);

        var path = GetTestFilePath($"ceq_r_{blockSize}.enc");
        WriteFile(path, data, MakeOptions(blockSize, concurrency: 1));

        var readC1 = ReadFile(path, size, MakeOptions(blockSize, concurrency: 1));
        var readC4 = ReadFile(path, size, MakeOptions(blockSize, concurrency: 4));

        readC1.Should().Equal(data, "C=1 read must match original");
        readC4.Should().Equal(data, "C=4 read must match original");
    }

    // ═══════════════════════════════════════════════════════════════════
    // Parallel write large file
    // ═══════════════════════════════════════════════════════════════════

    [Fact]
    public void ParallelWrite_LargeFile()
    {
        const int size = 1024 * 1024; // 1MB
        var data = GenerateRandomData(size);
        var path = GetTestFilePath("parallel_1mb.enc");

        WriteFile(path, data, MakeOptions(concurrency: 4));
        var result = ReadFile(path, size, MakeOptions(concurrency: 4));

        result.Should().Equal(data);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Multi-file different sizes
    // ═══════════════════════════════════════════════════════════════════

    [Fact]
    public void MultiFile_DifferentSizes()
    {
        int[] sizes = [100, 1024, 10 * 1024, 100 * 1024, 500 * 1024];
        var options = MakeOptions();

        for (int i = 0; i < sizes.Length; i++)
        {
            var data = GenerateRandomData(sizes[i]);
            var path = GetTestFilePath($"multi_{i}_{sizes[i]}.enc");

            WriteFile(path, data, options);
            var result = ReadFile(path, sizes[i], options);

            result.Should().Equal(data, $"file {i} ({sizes[i]} bytes) must round-trip correctly");
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Process restart simulation
    // ═══════════════════════════════════════════════════════════════════

    [Fact]
    public void ProcessRestartSimulation()
    {
        var data = GenerateRandomData(10_000);
        var path = GetTestFilePath("restart.enc");

        // Factory 1: write file
        using (var factory1 = new CipheredFileStreamFactory(_key))
        {
            using var stream = factory1.Create(path, FileMode.Create);
            stream.Write(data, 0, data.Length);
        }

        // Factory 2: simulate process restart with same key
        using (var factory2 = new CipheredFileStreamFactory(_key))
        {
            var buffer = new byte[data.Length];
            using var stream = factory2.Create(path, FileMode.Open, FileAccess.Read);
            int totalRead = 0;
            while (totalRead < data.Length)
            {
                int read = stream.Read(buffer, totalRead, data.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(data.Length);
            buffer.Should().Equal(data);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Block size header tests
    // ═══════════════════════════════════════════════════════════════════

    [Fact]
    public void ExistingFileIgnoresBlockSizeOption()
    {
        var data = GenerateRandomData(5000);
        var path = GetTestFilePath("ignorebs.enc");

        // Create with Block32K
        var createOptions = MakeOptions(BlockSizeOption.Block32K);
        WriteFile(path, data, createOptions);

        // Reopen with Block4K option -- header should determine actual block size
        var reopenOptions = MakeOptions(BlockSizeOption.Block4K);
        var result = ReadFile(path, data.Length, reopenOptions);

        result.Should().Equal(data);
    }

    [Fact]
    public void DefaultOptions_Uses16K()
    {
        var data = GenerateRandomData(100);
        var path = GetTestFilePath("default16k.enc");

        // Create with default options
        using (var stream = _factory.Create(path, FileMode.Create))
        {
            stream.Write(data, 0, data.Length);
        }

        var header = CipheredFileStreamFactory.ReadFileHeader(path);
        header.BlockSizeExponent.Should().Be(14, "default block size should be 16K (exponent 14)");
    }

    [Fact]
    public void HeaderContainsAlgorithmId()
    {
        var data = GenerateRandomData(100);
        var path = GetTestFilePath("algid.enc");

        using (var stream = _factory.Create(path, FileMode.Create))
        {
            stream.Write(data, 0, data.Length);
        }

        var header = CipheredFileStreamFactory.ReadFileHeader(path);
        header.AlgorithmId.Should().Be(0x01, "AES-GCM algorithm ID should be 0x01");
    }

    // ═══════════════════════════════════════════════════════════════════
    // Physical file size verification
    // ═══════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void PhysicalFileSize_Correct(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, GcmOverhead);
        var options = MakeOptions(blockSize);
        var path = GetTestFilePath($"physsize_{blockSize}.enc");

        // Write enough data to span multiple blocks
        int dataSize = layout.Block0DataCapacity + layout.BlockNDataCapacity * 2 + 1;
        var data = GenerateRandomData(dataSize);

        WriteFile(path, data, options);

        // Calculate expected block count:
        // block 0 holds Block0DataCapacity bytes
        // each subsequent block holds BlockNDataCapacity bytes
        int remaining = dataSize - layout.Block0DataCapacity;
        int extraBlocks = (remaining + layout.BlockNDataCapacity - 1) / layout.BlockNDataCapacity;
        int expectedBlockCount = 1 + extraBlocks;
        long expectedPhysicalSize = (long)expectedBlockCount * layout.BlockSize;

        new FileInfo(path).Length.Should().Be(expectedPhysicalSize,
            $"physical file should be {expectedBlockCount} blocks of {layout.BlockSize} bytes");

        // Also verify data round-trips correctly
        var result = ReadFile(path, dataSize, options);
        result.Should().Equal(data);
    }

    // ═══════════════════════════════════════════════════════════════════
    // EphemeralKeyProvider round-trip
    // ═══════════════════════════════════════════════════════════════════

    [Fact]
    public void EphemeralKeyProvider_RoundTrip()
    {
        var data = GenerateRandomData(5000);
        var path = GetTestFilePath("ephemeral.enc");

        using var keyProvider = new EphemeralKeyProvider();
        using var factory = new CipheredFileStreamFactory(keyProvider);

        // Write
        using (var stream = factory.Create(path, FileMode.Create))
        {
            stream.Write(data, 0, data.Length);
        }

        // Read back immediately with the same factory
        var buffer = new byte[data.Length];
        using (var stream = factory.Create(path, FileMode.Open, FileAccess.Read))
        {
            int totalRead = 0;
            while (totalRead < data.Length)
            {
                int read = stream.Read(buffer, totalRead, data.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            totalRead.Should().Be(data.Length);
        }

        buffer.Should().Equal(data);
    }
}
