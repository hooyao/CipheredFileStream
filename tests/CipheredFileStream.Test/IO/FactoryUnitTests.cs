using FluentAssertions;
using CipheredFileStream.IO;
using CipheredFileStream.IO.Exceptions;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class FactoryUnitTests : CryptoTestBase
{
    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Create_NewFile_Succeeds(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"new_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using var stream = _factory.Create(path, FileMode.Create, options);
        stream.Should().NotBeNull();
        stream.CanRead.Should().BeTrue();
        stream.CanWrite.Should().BeTrue();
        stream.CanSeek.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Create_OpenExisting_Succeeds(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"existing_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        // Create first
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(new byte[] { 1, 2, 3 }, 0, 3);
        }

        // Open
        using var stream2 = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream2.Length.Should().Be(3);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Create_OpenNonExistent_Throws(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"nonexistent_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        var act = () => _factory.Create(path, FileMode.Open, options);
        act.Should().Throw<FileNotFoundException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Create_CreateNew_OverExisting_Throws(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"existing_cn_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.WriteByte(1);
        }

        var act = () => _factory.Create(path, FileMode.CreateNew, options);
        act.Should().Throw<IOException>();
    }

    [Fact]
    public void Constructor_WrongKeySize_Throws()
    {
        var act = () => new CipheredFileStreamFactory(new byte[16]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_NullKey_Throws()
    {
        var act = () => new CipheredFileStreamFactory((byte[])null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ReadFileHeader_ReturnsCorrectInfo()
    {
        var path = GetTestFilePath("header.enc");

        var options = new CipheredFileStreamOptions { BlockSize = BlockSizeOption.Block32K };
        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.WriteByte(42);
        }

        var info = CipheredFileStreamFactory.ReadFileHeader(path);
        info.FormatVersion.Should().Be(0x0003);
        info.BlockSizeExponent.Should().Be(15); // Block32K
        info.AlgorithmId.Should().Be(0x01);     // AesGcm
        info.KdfMethod.Should().Be(KdfMethod.None);
    }

    [Fact]
    public void Dispose_ThenCreate_Throws()
    {
        var factory = new CipheredFileStreamFactory((byte[])_key.Clone());
        factory.Dispose();

        var act = () => factory.Create(GetTestFilePath("disposed.enc"), FileMode.Create);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void OpenOrCreate_CreatesIfMissing(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"openorcreate_new_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.OpenOrCreate, options);
        stream.Should().NotBeNull();
        stream.Length.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void OpenOrCreate_OpensIfExists(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"openorcreate_exists_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(new byte[] { 10, 20, 30, 40, 50 }, 0, 5);
        }

        using var stream2 = _factory.Create(path, FileMode.OpenOrCreate, options);
        stream2.Length.Should().Be(5);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Truncate_ClearsExistingContent(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"truncate_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(new byte[500], 0, 500);
        }

        using var stream2 = _factory.Create(path, FileMode.Truncate, options);
        stream2.Length.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void FileAccess_Read_CanRead(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"access_read_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.WriteByte(1);
        }

        using var stream2 = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream2.CanRead.Should().BeTrue();
        stream2.CanWrite.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void FileAccess_Read_WriteThrows(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"access_read_write_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.WriteByte(1);
        }

        using var stream2 = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        var act = () => stream2.WriteByte(99);
        act.Should().Throw<NotSupportedException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void FileAccess_ReadWrite_CanDoEither(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"access_rw_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using var stream = _factory.Create(path, FileMode.Create, FileAccess.ReadWrite, options);
        stream.CanRead.Should().BeTrue();
        stream.CanWrite.Should().BeTrue();

        stream.WriteByte(42);
        stream.Seek(0, SeekOrigin.Begin);
        stream.ReadByte().Should().Be(42);
    }

    [Fact]
    public void OpenNonEncryptedFile_Throws()
    {
        var path = GetTestFilePath("plaintext.txt");
        File.WriteAllText(path, "This is not an encrypted file.");

        var act = () => _factory.Create(path, FileMode.Open);
        act.Should().Throw<EncryptedFileCorruptException>();
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void FileMode_Create_OverwritesExisting(BlockSizeOption blockSize)
    {
        var path = GetTestFilePath($"overwrite_{blockSize}.enc");
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var stream = _factory.Create(path, FileMode.Create, options))
        {
            stream.Write(new byte[1024], 0, 1024);
        }

        using (var stream2 = _factory.Create(path, FileMode.Create, options))
        {
            stream2.Write(new byte[500], 0, 500);
        }

        using var stream3 = _factory.Create(path, FileMode.Open, FileAccess.Read, options);
        stream3.Length.Should().Be(500);
    }
}
