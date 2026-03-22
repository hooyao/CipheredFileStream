using CipheredFileStream.IO;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Shared base class for all crypto/IO tests.
/// Provides temp directory, random key, factory, and block size test data.
/// </summary>
public abstract class CryptoTestBase : IDisposable
{
    private const string TestPrefix = "CFS_Test";

    protected readonly string _testDir;
    protected readonly byte[] _key;
    protected readonly CipheredFileStreamFactory _factory;

    protected CryptoTestBase()
    {
        var tempRoot = Environment.GetEnvironmentVariable("CFS_TEST_TEMP") ?? Path.GetTempPath();
        _testDir = Path.Combine(tempRoot, $"{TestPrefix}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);

        _key = new byte[EncryptedFileFormat.KeySize];
        Random.Shared.NextBytes(_key);

        _factory = new CipheredFileStreamFactory(_key);
    }

    /// <summary>
    /// All supported block sizes for parameterized tests.
    /// </summary>
    public static IEnumerable<object[]> AllBlockSizes =>
    [
        [BlockSizeOption.Block4K],
        [BlockSizeOption.Block8K],
        [BlockSizeOption.Block16K],
        [BlockSizeOption.Block32K],
        [BlockSizeOption.Block64K],
        [BlockSizeOption.Block128K],
    ];

    protected string GetTestFilePath(string name = "test.enc")
        => Path.Combine(_testDir, name);

    protected static byte[] GenerateRandomData(int size)
    {
        var data = new byte[size];
        Random.Shared.NextBytes(data);
        return data;
    }

    public void Dispose()
    {
        _factory.Dispose();
        try
        {
            if (Directory.Exists(_testDir))
                Directory.Delete(_testDir, true);
        }
        catch
        {
            // Best effort cleanup
        }
    }
}
