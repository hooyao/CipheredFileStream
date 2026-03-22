using System.Diagnostics;
using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;
using Xunit.Abstractions;

namespace CipheredFileStream.Test.IO;

public class CryptoBenchmarkTests : CryptoTestBase
{
    private readonly ITestOutputHelper _output;

    public CryptoBenchmarkTests(ITestOutputHelper output) : base()
    {
        _output = output;
    }

    // ── Encrypt All Payload Sizes ───────────────────────────────────────────

    [Trait("Category", "Benchmark")]
    [Fact]
    public void AesGcm_Encrypt_AllPayloadSizes()
    {
        const long totalBytes = 256L * 1024 * 1024;
        const int warmupCalls = 100;

        _output.WriteLine("AES-GCM Encrypt Throughput — All Block Sizes:");
        _output.WriteLine($"  {"BlockSize",-12} {"Payload",10} {"MB/s",12} {"Time ms",12}");
        _output.WriteLine($"  {new string('-', 46)}");

        foreach (BlockSizeOption blockSize in Enum.GetValues<BlockSizeOption>())
        {
            var layout = new BlockLayout((int)blockSize, 28);
            int payloadSize = layout.PayloadCapacity;
            int ciphertextSize = payloadSize + 28;
            int iterations = (int)(totalBytes / payloadSize);

            var crypto = new AesGcmBlockCrypto();
            var plaintext = new byte[payloadSize];
            var ciphertext = new byte[ciphertextSize];
            var integrityTag = new byte[32];
            var aad = new byte[8];
            Random.Shared.NextBytes(plaintext);
            Random.Shared.NextBytes(aad);

            // Warmup
            for (int i = 0; i < warmupCalls; i++)
                crypto.Encrypt(_key, plaintext, 0, payloadSize, aad, ciphertext, 0, integrityTag);

            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
                crypto.Encrypt(_key, plaintext, 0, payloadSize, aad, ciphertext, 0, integrityTag);
            sw.Stop();

            double elapsedMs = sw.Elapsed.TotalMilliseconds;
            long processedBytes = (long)iterations * payloadSize;
            double mbps = processedBytes / (1024.0 * 1024.0) / (elapsedMs / 1000.0);

            _output.WriteLine($"  {blockSize,-12} {payloadSize,10} {mbps,12:F1} {elapsedMs,12:F1}");

            crypto.Dispose();
        }
    }

    // ── Decrypt All Payload Sizes ───────────────────────────────────────────

    [Trait("Category", "Benchmark")]
    [Fact]
    public void AesGcm_Decrypt_AllPayloadSizes()
    {
        const long totalBytes = 256L * 1024 * 1024;
        const int warmupCalls = 100;

        _output.WriteLine("AES-GCM Decrypt Throughput — All Block Sizes:");
        _output.WriteLine($"  {"BlockSize",-12} {"Payload",10} {"MB/s",12} {"Time ms",12}");
        _output.WriteLine($"  {new string('-', 46)}");

        foreach (BlockSizeOption blockSize in Enum.GetValues<BlockSizeOption>())
        {
            var layout = new BlockLayout((int)blockSize, 28);
            int payloadSize = layout.PayloadCapacity;
            int ciphertextSize = payloadSize + 28;
            int iterations = (int)(totalBytes / payloadSize);

            var crypto = new AesGcmBlockCrypto();
            var plaintext = new byte[payloadSize];
            var ciphertext = new byte[ciphertextSize];
            var decrypted = new byte[payloadSize];
            var integrityTag = new byte[32];
            var aad = new byte[8];
            Random.Shared.NextBytes(plaintext);
            Random.Shared.NextBytes(aad);

            // Pre-encrypt all blocks with the same buffer (content doesn't matter for benchmarking)
            crypto.Encrypt(_key, plaintext, 0, payloadSize, aad, ciphertext, 0, integrityTag);

            // Warmup
            for (int i = 0; i < warmupCalls; i++)
                crypto.Decrypt(_key, ciphertext, 0, ciphertextSize, aad, decrypted, 0, integrityTag);

            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
                crypto.Decrypt(_key, ciphertext, 0, ciphertextSize, aad, decrypted, 0, integrityTag);
            sw.Stop();

            double elapsedMs = sw.Elapsed.TotalMilliseconds;
            long processedBytes = (long)iterations * payloadSize;
            double mbps = processedBytes / (1024.0 * 1024.0) / (elapsedMs / 1000.0);

            _output.WriteLine($"  {blockSize,-12} {payloadSize,10} {mbps,12:F1} {elapsedMs,12:F1}");

            crypto.Dispose();
        }
    }

    // ── Encrypt Pipeline Detailed Timing 16K ────────────────────────────────

    [Trait("Category", "Benchmark")]
    [Fact]
    public void EncryptPipeline_DetailedTiming_16K()
    {
        const int payloadSize = 16384;
        const int iterations = 10000;
        const int warmupCalls = 100;

        var crypto = new AesGcmBlockCrypto();
        var plaintext = new byte[payloadSize];
        var ciphertext = new byte[payloadSize + 28];
        var integrityTag = new byte[32];
        var aad = new byte[8];
        Random.Shared.NextBytes(plaintext);

        // Warmup
        for (int i = 0; i < warmupCalls; i++)
            crypto.Encrypt(_key, plaintext, 0, payloadSize, aad, ciphertext, 0, integrityTag);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
            crypto.Encrypt(_key, plaintext, 0, payloadSize, aad, ciphertext, 0, integrityTag);
        sw.Stop();

        double totalMs = sw.Elapsed.TotalMilliseconds;
        double usPerCall = totalMs / iterations * 1000.0;
        long totalBytesProcessed = (long)iterations * payloadSize;
        double mbps = totalBytesProcessed / (1024.0 * 1024.0) / (totalMs / 1000.0);

        _output.WriteLine($"Encrypt Pipeline Detailed Timing (16K payload, {iterations} iterations):");
        _output.WriteLine($"  Total time   : {totalMs:F1} ms");
        _output.WriteLine($"  Per call     : {usPerCall:F2} us");
        _output.WriteLine($"  Throughput   : {mbps:F1} MB/s");

        crypto.Dispose();

        mbps.Should().BeGreaterThan(0);
    }

    // ── Decrypt Pipeline Detailed Timing 16K ────────────────────────────────

    [Trait("Category", "Benchmark")]
    [Fact]
    public void DecryptPipeline_DetailedTiming_16K()
    {
        const int payloadSize = 16384;
        const int iterations = 10000;
        const int warmupCalls = 100;

        var crypto = new AesGcmBlockCrypto();
        var plaintext = new byte[payloadSize];
        var ciphertext = new byte[payloadSize + 28];
        var decrypted = new byte[payloadSize];
        var integrityTag = new byte[32];
        var aad = new byte[8];
        Random.Shared.NextBytes(plaintext);

        // Pre-encrypt
        crypto.Encrypt(_key, plaintext, 0, payloadSize, aad, ciphertext, 0, integrityTag);

        // Warmup
        for (int i = 0; i < warmupCalls; i++)
            crypto.Decrypt(_key, ciphertext, 0, ciphertext.Length, aad, decrypted, 0, integrityTag);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
            crypto.Decrypt(_key, ciphertext, 0, ciphertext.Length, aad, decrypted, 0, integrityTag);
        sw.Stop();

        double totalMs = sw.Elapsed.TotalMilliseconds;
        double usPerCall = totalMs / iterations * 1000.0;
        long totalBytesProcessed = (long)iterations * payloadSize;
        double mbps = totalBytesProcessed / (1024.0 * 1024.0) / (totalMs / 1000.0);

        _output.WriteLine($"Decrypt Pipeline Detailed Timing (16K payload, {iterations} iterations):");
        _output.WriteLine($"  Total time   : {totalMs:F1} ms");
        _output.WriteLine($"  Per call     : {usPerCall:F2} us");
        _output.WriteLine($"  Throughput   : {mbps:F1} MB/s");

        crypto.Dispose();

        mbps.Should().BeGreaterThan(0);
    }

    // ── Encrypt+Decrypt Round Trip Throughput ────────────────────────────────

    [Trait("Category", "Benchmark")]
    [Theory]
    [InlineData(4096)]
    [InlineData(16384)]
    [InlineData(131072)]
    public void EncryptDecrypt_RoundTrip_Throughput(int payloadSize)
    {
        const long totalBytes = 256L * 1024 * 1024;
        const int warmupCalls = 100;
        int iterations = (int)(totalBytes / payloadSize);

        var crypto = new AesGcmBlockCrypto();
        var plaintext = new byte[payloadSize];
        var ciphertext = new byte[payloadSize + 28];
        var decrypted = new byte[payloadSize];
        var integrityTag = new byte[32];
        var aad = new byte[8];
        Random.Shared.NextBytes(plaintext);

        // Warmup
        for (int i = 0; i < warmupCalls; i++)
        {
            crypto.Encrypt(_key, plaintext, 0, payloadSize, aad, ciphertext, 0, integrityTag);
            crypto.Decrypt(_key, ciphertext, 0, ciphertext.Length, aad, decrypted, 0, integrityTag);
        }

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            crypto.Encrypt(_key, plaintext, 0, payloadSize, aad, ciphertext, 0, integrityTag);
            crypto.Decrypt(_key, ciphertext, 0, ciphertext.Length, aad, decrypted, 0, integrityTag);
        }
        sw.Stop();

        double totalMs = sw.Elapsed.TotalMilliseconds;
        // Each iteration processes payloadSize bytes through encrypt AND decrypt
        long processedBytes = (long)iterations * payloadSize * 2;
        double mbps = processedBytes / (1024.0 * 1024.0) / (totalMs / 1000.0);

        _output.WriteLine($"Encrypt+Decrypt Round Trip (payload={payloadSize}, {iterations} iterations):");
        _output.WriteLine($"  Total time  : {totalMs:F1} ms");
        _output.WriteLine($"  Throughput  : {mbps:F1} MB/s (combined encrypt+decrypt)");

        crypto.Dispose();

        mbps.Should().BeGreaterThan(0);
    }

    // ── Overhead Comparison All Sizes ────────────────────────────────────────

    [Trait("Category", "Benchmark")]
    [Fact]
    public void Overhead_Comparison_AllSizes()
    {
        const int ciphertextOverhead = 28;

        _output.WriteLine("Ciphertext Overhead — All Block Sizes:");
        _output.WriteLine($"  {"BlockSize",-12} {"Payload",10} {"Overhead",10} {"Overhead %",12}");
        _output.WriteLine($"  {new string('-', 44)}");

        foreach (BlockSizeOption blockSize in Enum.GetValues<BlockSizeOption>())
        {
            var layout = new BlockLayout((int)blockSize, ciphertextOverhead);
            int payloadCapacity = layout.PayloadCapacity;
            double overheadPct = (double)ciphertextOverhead / (payloadCapacity + ciphertextOverhead) * 100.0;

            _output.WriteLine($"  {blockSize,-12} {payloadCapacity,10} {ciphertextOverhead,10} {overheadPct,12:F3}%");
        }
    }
}
