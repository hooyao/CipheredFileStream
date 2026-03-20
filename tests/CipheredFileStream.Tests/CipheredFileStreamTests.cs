using System.Security.Cryptography;
using CipheredFileStream;

namespace CipheredFileStream.Tests;

public class CipheredFileStreamTests : IDisposable
{
    private readonly string _tempDir;
    private static readonly byte[] TestKey = RandomNumberGenerator.GetBytes(32);

    public CipheredFileStreamTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"CipheredTest_{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private string GetTempPath(string name) => Path.Combine(_tempDir, name);

    [Fact]
    public void Create_And_Read_EmptyFile()
    {
        var path = GetTempPath("empty.cfs");

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            Assert.Equal(0, cfs.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            Assert.Equal(0, cfs.Length);
            var buffer = new byte[100];
            Assert.Equal(0, cfs.Read(buffer, 0, buffer.Length));
        }
    }

    [Theory]
    [InlineData(ChunkSize.Size4K)]
    [InlineData(ChunkSize.Size8K)]
    [InlineData(ChunkSize.Size16K)]
    [InlineData(ChunkSize.Size32K)]
    [InlineData(ChunkSize.Size64K)]
    [InlineData(ChunkSize.Size128K)]
    public void Write_And_Read_WithDifferentChunkSizes(ChunkSize chunkSize)
    {
        var path = GetTempPath($"chunk_{chunkSize}.cfs");
        var chunkSizeBytes = (int)chunkSize;
        var data = RandomNumberGenerator.GetBytes(chunkSizeBytes * 3 + 100);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey, chunkSize))
        {
            cfs.Write(data, 0, data.Length);
            Assert.Equal(data.Length, cfs.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey, chunkSize))
        {
            Assert.Equal(data.Length, cfs.Length);
            var readBuffer = new byte[data.Length];
            var totalRead = 0;
            while (totalRead < data.Length)
            {
                var read = cfs.Read(readBuffer, totalRead, data.Length - totalRead);
                Assert.True(read > 0);
                totalRead += read;
            }
            Assert.Equal(data, readBuffer);
        }
    }

    [Fact]
    public void ReadWrite_CompareWithFileStream_SequentialWrite()
    {
        var plainPath = GetTempPath("plain.bin");
        var cipherPath = GetTempPath("cipher.cfs");
        var data = RandomNumberGenerator.GetBytes(10000);

        // Write with FileStream
        using (var fs = new FileStream(plainPath, FileMode.Create, FileAccess.Write))
        {
            fs.Write(data, 0, data.Length);
        }

        // Write with CipheredFileStream
        using (var cfs = new CipheredFileStream(cipherPath, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
        }

        // Read with CipheredFileStream
        using (var cfs = new CipheredFileStream(cipherPath, FileMode.Open, FileAccess.Read, TestKey))
        {
            var readBuffer = new byte[data.Length];
            var totalRead = 0;
            while (totalRead < data.Length)
            {
                var read = cfs.Read(readBuffer, totalRead, data.Length - totalRead);
                totalRead += read;
            }
            Assert.Equal(data, readBuffer);
        }
    }

    [Fact]
    public void ReadWrite_CompareWithFileStream_RandomRead()
    {
        var plainPath = GetTempPath("plain_random.bin");
        var cipherPath = GetTempPath("cipher_random.cfs");
        var data = RandomNumberGenerator.GetBytes(10000);

        // Write with FileStream
        using (var fs = new FileStream(plainPath, FileMode.Create, FileAccess.Write))
        {
            fs.Write(data, 0, data.Length);
        }

        // Write with CipheredFileStream
        using (var cfs = new CipheredFileStream(cipherPath, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
        }

        // Random reads should match
        using var fsRead = new FileStream(plainPath, FileMode.Open, FileAccess.Read);
        using var cfsRead = new CipheredFileStream(cipherPath, FileMode.Open, FileAccess.Read, TestKey);

        var positions = new[] { 0, 100, 500, 1000, 4096, 5000, 8192, 9999 };
        var readLen = 50;

        foreach (var pos in positions)
        {
            if (pos + readLen > data.Length) continue;

            fsRead.Position = pos;
            cfsRead.Position = pos;

            var fsBuf = new byte[readLen];
            var cfsBuf = new byte[readLen];

            fsRead.ReadExactly(fsBuf, 0, readLen);
            cfsRead.ReadExactly(cfsBuf, 0, readLen);

            Assert.Equal(fsBuf, cfsBuf);
        }
    }

    [Fact]
    public void Seek_FromBegin_Current_End()
    {
        var path = GetTempPath("seek.cfs");
        var data = RandomNumberGenerator.GetBytes(1000);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            // Seek from begin
            cfs.Seek(100, SeekOrigin.Begin);
            Assert.Equal(100, cfs.Position);

            // Seek from current
            cfs.Seek(50, SeekOrigin.Current);
            Assert.Equal(150, cfs.Position);

            // Seek from end
            cfs.Seek(-100, SeekOrigin.End);
            Assert.Equal(900, cfs.Position);

            // Read after seek
            cfs.Seek(0, SeekOrigin.Begin);
            var buf = new byte[100];
            cfs.ReadExactly(buf, 0, 100);
            Assert.Equal(data.AsSpan(0, 100).ToArray(), buf);
        }
    }

    [Fact]
    public void Write_InMiddle_Overwrite()
    {
        var path = GetTempPath("overwrite.cfs");
        var data = new byte[1000];
        Array.Fill(data, (byte)0xAA);

        var overwrite = new byte[200];
        Array.Fill(overwrite, (byte)0xBB);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
            cfs.Position = 300;
            cfs.Write(overwrite, 0, overwrite.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            var readBuffer = new byte[1000];
            cfs.ReadExactly(readBuffer);

            // Check original data before overwrite
            for (int i = 0; i < 300; i++)
                Assert.Equal(0xAA, readBuffer[i]);

            // Check overwritten section
            for (int i = 300; i < 500; i++)
                Assert.Equal(0xBB, readBuffer[i]);

            // Check original data after overwrite
            for (int i = 500; i < 1000; i++)
                Assert.Equal(0xAA, readBuffer[i]);
        }
    }

    [Fact]
    public void SetLength_Truncate()
    {
        var path = GetTempPath("truncate.cfs");
        var data = RandomNumberGenerator.GetBytes(1000);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
            cfs.SetLength(500);
            Assert.Equal(500, cfs.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            Assert.Equal(500, cfs.Length);
            var readBuffer = new byte[500];
            cfs.ReadExactly(readBuffer);
            Assert.Equal(data.AsSpan(0, 500).ToArray(), readBuffer);
        }
    }

    [Fact]
    public void SetLength_Extend()
    {
        var path = GetTempPath("extend.cfs");
        var data = RandomNumberGenerator.GetBytes(500);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
            cfs.SetLength(1000);
            Assert.Equal(1000, cfs.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            Assert.Equal(1000, cfs.Length);
        }
    }

    [Fact]
    public void Password_Based_Encryption()
    {
        var path = GetTempPath("password.cfs");
        var password = "TestPassword123!";
        var data = RandomNumberGenerator.GetBytes(1000);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, password))
        {
            cfs.Write(data, 0, data.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, password))
        {
            var readBuffer = new byte[data.Length];
            cfs.ReadExactly(readBuffer);
            Assert.Equal(data, readBuffer);
        }

        // Wrong password should fail
        Assert.ThrowsAny<Exception>(() =>
        {
            using var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, "WrongPassword");
            var buf = new byte[100];
            cfs.ReadExactly(buf);
        });
    }

    [Fact]
    public void VerifyIntegrity_Valid()
    {
        var path = GetTempPath("integrity.cfs");
        var data = RandomNumberGenerator.GetBytes(1000);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            cfs.VerifyIntegrity();
        }
    }

    [Fact]
    public void VerifyIntegrity_Corrupted()
    {
        var path = GetTempPath("corrupted.cfs");
        var data = RandomNumberGenerator.GetBytes(10000);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
        }

        // Corrupt the file by modifying bytes in a chunk
        var fileBytes = File.ReadAllBytes(path);
        fileBytes[100] ^= 0xFF;
        File.WriteAllBytes(path, fileBytes);

        // Opening should fail due to magic number or header corruption
        // or reading should fail due to AES-GCM auth failure
        Assert.ThrowsAny<Exception>(() =>
        {
            using var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey);
            cfs.VerifyIntegrity();
        });
    }

    [Fact]
    public void NotCipheredFileStream_Throws()
    {
        var path = GetTempPath("notcfs.bin");
        File.WriteAllBytes(path, new byte[100]);

        Assert.Throws<InvalidDataException>(() =>
        {
            using var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey);
        });
    }

    [Fact]
    public void LargeFile_MultipleChunks()
    {
        var path = GetTempPath("large.cfs");
        var chunkSize = ChunkSize.Size4K;
        var chunkSizeBytes = (int)chunkSize;
        var numChunks = 10;
        var data = RandomNumberGenerator.GetBytes(chunkSizeBytes * numChunks);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey, chunkSize))
        {
            cfs.Write(data, 0, data.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey, chunkSize))
        {
            Assert.Equal(data.Length, cfs.Length);
            var readBuffer = new byte[data.Length];
            cfs.ReadExactly(readBuffer);
            Assert.Equal(data, readBuffer);
        }
    }

    [Fact]
    public void WriteAsync_ReadAsync()
    {
        var path = GetTempPath("async.cfs");
        var data = RandomNumberGenerator.GetBytes(5000);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.WriteAsync(data, 0, data.Length).Wait();
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            var readBuffer = new byte[data.Length];
            var totalRead = 0;
            while (totalRead < data.Length)
            {
                var read = cfs.ReadAsync(readBuffer, totalRead, data.Length - totalRead).Result;
                totalRead += read;
            }
            Assert.Equal(data, readBuffer);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(4095)]
    [InlineData(4096)]
    [InlineData(4097)]
    [InlineData(10000)]
    public void VariousDataSizes(int size)
    {
        var path = GetTempPath($"size_{size}.cfs");
        var data = size > 0 ? RandomNumberGenerator.GetBytes(size) : Array.Empty<byte>();

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            if (data.Length > 0)
                cfs.Write(data, 0, data.Length);
            Assert.Equal(size, cfs.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            Assert.Equal(size, cfs.Length);
            if (size > 0)
            {
                var readBuffer = new byte[size];
                var totalRead = 0;
                while (totalRead < size)
                {
                    var read = cfs.Read(readBuffer, totalRead, size - totalRead);
                    Assert.True(read > 0);
                    totalRead += read;
                }
                Assert.Equal(data, readBuffer);
            }
        }
    }

    [Fact]
    public void Disposed_ThrowsObjectDisposed()
    {
        var path = GetTempPath("disposed.cfs");
        var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey);
        cfs.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cfs.Write(new byte[1], 0, 1));
        Assert.Throws<ObjectDisposedException>(() => cfs.Read(new byte[1], 0, 1));
        Assert.Throws<ObjectDisposedException>(() => cfs.Flush());
        Assert.Throws<ObjectDisposedException>(() => cfs.Seek(0, SeekOrigin.Begin));
    }

    [Fact]
    public void Read_Only_ThrowsOnWrite()
    {
        var path = GetTempPath("readonly.cfs");

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(new byte[100], 0, 100);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            Assert.Throws<InvalidOperationException>(() => cfs.Write(new byte[1], 0, 1));
        }
    }

    [Fact]
    public void Write_Only_ThrowsOnRead()
    {
        var path = GetTempPath("writeonly.cfs");

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            Assert.Throws<InvalidOperationException>(() => cfs.Read(new byte[1], 0, 1));
        }
    }

    [Fact]
    public void CreateNew_ThrowsIfExists()
    {
        var path = GetTempPath("createnew.cfs");

        using (var cfs = new CipheredFileStream(path, FileMode.CreateNew, FileAccess.Write, TestKey))
        {
            cfs.Write(new byte[100], 0, 100);
        }

        Assert.Throws<IOException>(() =>
        {
            using var cfs = new CipheredFileStream(path, FileMode.CreateNew, FileAccess.Write, TestKey);
        });
    }

    [Fact]
    public void CrossChunk_Read()
    {
        var path = GetTempPath("crosschunk.cfs");
        var chunkSize = 4096;
        var data = RandomNumberGenerator.GetBytes(chunkSize * 2 + 500);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            // Read spanning two chunks
            cfs.Position = chunkSize - 100;
            var buf = new byte[300];
            cfs.ReadExactly(buf);
            Assert.Equal(data.AsSpan(chunkSize - 100, 300).ToArray(), buf);
        }
    }

    [Fact]
    public void UpdateChunk_UpdatesTotalChecksum()
    {
        var path = GetTempPath("update_checksum.cfs");
        var data = RandomNumberGenerator.GetBytes(10000);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data, 0, data.Length);
        }

        // Read original file bytes
        var originalBytes = File.ReadAllBytes(path);

        // Open and modify a chunk
        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Write, TestKey))
        {
            cfs.Position = 5000;
            cfs.Write(new byte[100], 0, 100);
        }

        // File should be different (checksum updated)
        var modifiedBytes = File.ReadAllBytes(path);
        Assert.NotEqual(originalBytes, modifiedBytes);

        // Should still be readable and verify integrity
        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            cfs.VerifyIntegrity();
            var buf = new byte[10000];
            cfs.ReadExactly(buf);
            // Modified section should be zeros
            for (int i = 5000; i < 5100; i++)
                Assert.Equal(0, buf[i]);
        }
    }

    [Fact]
    public void Multiple_Flushes()
    {
        var path = GetTempPath("multiflush.cfs");

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(new byte[100], 0, 100);
            cfs.Flush();
            cfs.Write(new byte[100], 0, 100);
            cfs.Flush();
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            Assert.Equal(200, cfs.Length);
        }
    }

    [Fact]
    public void Span_Overloads()
    {
        var path = GetTempPath("span.cfs");
        var data = RandomNumberGenerator.GetBytes(1000);

        using (var cfs = new CipheredFileStream(path, FileMode.Create, FileAccess.Write, TestKey))
        {
            cfs.Write(data.AsSpan());
        }

        using (var cfs = new CipheredFileStream(path, FileMode.Open, FileAccess.Read, TestKey))
        {
            var readBuffer = new byte[data.Length];
            var totalRead = 0;
            while (totalRead < data.Length)
            {
                var read = cfs.Read(readBuffer.AsSpan(totalRead));
                totalRead += read;
            }
            Assert.Equal(data, readBuffer);
        }
    }
}
