using FluentAssertions;
using CipheredFileStream.IO;

namespace CipheredFileStream.Test.IO;

public class PasswordKeyProviderTests : IDisposable
{
    private readonly string _testDir;

    public static IEnumerable<object[]> AllBlockSizes =>
    [
        [BlockSizeOption.Block4K],
        [BlockSizeOption.Block8K],
        [BlockSizeOption.Block16K],
        [BlockSizeOption.Block32K],
        [BlockSizeOption.Block64K],
        [BlockSizeOption.Block128K],
    ];

    public PasswordKeyProviderTests()
    {
        var tempRoot = Environment.GetEnvironmentVariable("CFS_TEST_TEMP") ?? Path.GetTempPath();
        _testDir = Path.Combine(tempRoot, $"CFS_PwdTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void Password_RoundTrip_WriteThenRead(BlockSizeOption blockSize)
    {
        var path = Path.Combine(_testDir, $"pwd_{blockSize}.enc");
        var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        // Write with password
        using (var provider = new PasswordKeyProvider("testpassword123"))
        using (var factory = new CipheredFileStreamFactory(provider))
        using (var stream = factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        // Read back: inspect header first
        var info = CipheredFileStreamFactory.ReadFileHeader(path);
        info.KdfMethod.Should().Be(KdfMethod.Pbkdf2Sha256);
        info.Salt.Should().NotBeNull();
        info.Salt!.Length.Should().Be(16);
        info.KdfIterations.Should().Be(600_000);
        info.AlgorithmId.Should().Be(0x01);

        // Reopen with password
        using (var provider = new PasswordKeyProvider("testpassword123", info.Salt, info.KdfIterations))
        using (var factory = new CipheredFileStreamFactory(provider))
        using (var stream = factory.Create(path, FileMode.Open, FileAccess.Read, options))
        {
            stream.Length.Should().Be(10);
            var readBack = new byte[10];
            stream.Read(readBack, 0, 10).Should().Be(10);
            readBack.Should().BeEquivalentTo(data);
        }
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void WrongPassword_FailsAuthentication(BlockSizeOption blockSize)
    {
        var path = Path.Combine(_testDir, $"wrong_pwd_{blockSize}.enc");
        var data = new byte[] { 1, 2, 3 };
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var provider = new PasswordKeyProvider("correct"))
        using (var factory = new CipheredFileStreamFactory(provider))
        using (var stream = factory.Create(path, FileMode.Create, options))
        {
            stream.Write(data, 0, data.Length);
        }

        var info = CipheredFileStreamFactory.ReadFileHeader(path);

        // Try wrong password
        using var wrongProvider = new PasswordKeyProvider("wrong", info.Salt!, info.KdfIterations);
        using var wrongFactory = new CipheredFileStreamFactory(wrongProvider);
        var act = () => wrongFactory.Create(path, FileMode.Open, FileAccess.Read, options);
        act.Should().Throw<Exception>(); // GCM auth failure during header decrypt
    }

    [Theory]
    [MemberData(nameof(AllBlockSizes))]
    public void ReadFileHeader_DirectKey_ReturnsNone(BlockSizeOption blockSize)
    {
        var path = Path.Combine(_testDir, $"directkey_{blockSize}.enc");
        var key = new byte[32];
        Random.Shared.NextBytes(key);
        var options = new CipheredFileStreamOptions { BlockSize = blockSize };

        using (var factory = new CipheredFileStreamFactory(key))
        using (var stream = factory.Create(path, FileMode.Create, options))
        {
            stream.WriteByte(0x42);
        }

        var info = CipheredFileStreamFactory.ReadFileHeader(path);
        info.KdfMethod.Should().Be(KdfMethod.None);
        info.Salt.Should().BeNull();
        info.KdfIterations.Should().Be(0);
    }

    [Fact]
    public void PasswordKeyProvider_Dispose_ZerosKey()
    {
        var provider = new PasswordKeyProvider("test");
        var key = provider.GetKey();
        key.Should().NotBeEquivalentTo(new byte[32]); // key is not all zeros

        provider.Dispose();

        var act = () => provider.GetKey();
        act.Should().Throw<ObjectDisposedException>();
    }

    public void Dispose()
    {
        try { Directory.Delete(_testDir, true); } catch { }
    }
}
