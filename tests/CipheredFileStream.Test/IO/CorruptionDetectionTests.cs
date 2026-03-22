using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Exceptions;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class CorruptionDetectionTests : CryptoTestBase
{
    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void FlippedCiphertextByte_ThrowsOnRead(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"corrupt_{blockSize}.enc");
        var data = GenerateRandomData(1000);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.Write(data, 0, data.Length);

        // Corrupt a byte in the encrypted area (after 32B header + 4B length prefix)
        var fileBytes = File.ReadAllBytes(path);
        fileBytes[50] ^= 0xFF;
        File.WriteAllBytes(path, fileBytes);

        // Reading should fail
        var act = () =>
        {
            using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
            var buf = new byte[1000];
            stream.ReadExactly(buf, 0, 1000);
        };
        act.Should().Throw<EncryptedFileCorruptException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void InvalidMagicBytes_Throws(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"badmagic_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.WriteByte(42);

        // Overwrite magic bytes
        var fileBytes = File.ReadAllBytes(path);
        fileBytes[0] = 0xFF;
        fileBytes[1] = 0xFF;
        File.WriteAllBytes(path, fileBytes);

        var act = () =>
        {
            using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        };
        act.Should().Throw<EncryptedFileCorruptException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void UnsupportedVersion_Throws(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"badver_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.WriteByte(42);

        // Set version to 0xFFFF
        var fileBytes = File.ReadAllBytes(path);
        fileBytes[2] = 0xFF;
        fileBytes[3] = 0xFF;
        File.WriteAllBytes(path, fileBytes);

        var act = () =>
        {
            using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        };
        act.Should().Throw<EncryptedFileVersionException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void CorruptedIV_ThrowsOnRead(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"corruptiv_{blockSize}.enc");
        var data = GenerateRandomData(1024);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.Write(data, 0, data.Length);

        // Flip a byte at offset 36 (within GCM nonce area: header 32 + length prefix 4 + nonce starts)
        var fileBytes = File.ReadAllBytes(path);
        fileBytes[36] ^= 0xFF;
        File.WriteAllBytes(path, fileBytes);

        var act = () =>
        {
            using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
            var buf = new byte[1024];
            stream.ReadExactly(buf, 0, buf.Length);
        };
        act.Should().Throw<EncryptedFileCorruptException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void TruncatedBlock_ThrowsOnRead(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        // Write enough data to guarantee at least 3 blocks
        var dataSize = layout.Block0DataCapacity + layout.BlockNDataCapacity * 2 + 100;
        var path = GetTestFilePath($"truncblock_{blockSize}.enc");
        var data = GenerateRandomData(dataSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.Write(data, 0, data.Length);

        // Overwrite block 2's ciphertext length prefix with a value larger than
        // the remaining bytes in the file, so reading that block triggers a corruption error.
        var fileBytes = File.ReadAllBytes(path);
        int block2Offset = layout.BlockSize * 2; // physical start of block 2
        // Write a ciphertext length that exceeds BlockNMaxCiphertextSize
        BitConverter.TryWriteBytes(fileBytes.AsSpan(block2Offset), (uint)(layout.BlockNMaxCiphertextSize + 1));
        File.WriteAllBytes(path, fileBytes);

        var act = () =>
        {
            using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
            var buf = new byte[dataSize];
            int totalRead = 0;
            while (totalRead < buf.Length)
            {
                int read = stream.Read(buf, totalRead, buf.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
        };
        act.Should().Throw<Exception>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ZeroLengthCiphertext_ThrowsOnRead(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"zerolen_{blockSize}.enc");
        var data = GenerateRandomData(1024);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.Write(data, 0, data.Length);

        // Zero out the 4-byte ciphertext length prefix at offset 32 (after header)
        var fileBytes = File.ReadAllBytes(path);
        fileBytes[32] = 0;
        fileBytes[33] = 0;
        fileBytes[34] = 0;
        fileBytes[35] = 0;
        File.WriteAllBytes(path, fileBytes);

        var act = () =>
        {
            using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
            var buf = new byte[1024];
            stream.ReadExactly(buf, 0, buf.Length);
        };
        act.Should().Throw<Exception>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void CorruptMiddleBlock_ThrowsOnRead(BlockSizeOption blockSize)
    {
        var layout = new BlockLayout((int)blockSize, 28);
        // Write enough data for 3+ blocks
        var dataSize = layout.Block0DataCapacity + layout.BlockNDataCapacity * 2 + 1;
        var path = GetTestFilePath($"corruptmid_{blockSize}.enc");
        var data = GenerateRandomData(dataSize);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var s = _factory.Create(path, FileMode.Create, options))
            s.Write(data, 0, data.Length);

        // Flip byte in block 1's ciphertext area (offset = blockSize + 40)
        var fileBytes = File.ReadAllBytes(path);
        var corruptOffset = layout.BlockSize + 40;
        fileBytes[corruptOffset] ^= 0xFF;
        File.WriteAllBytes(path, fileBytes);

        var act = () =>
        {
            using var stream = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
            var buf = new byte[dataSize];
            int totalRead = 0;
            while (totalRead < buf.Length)
            {
                int read = stream.Read(buf, totalRead, buf.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
        };
        act.Should().Throw<EncryptedFileCorruptException>();
    }
}
