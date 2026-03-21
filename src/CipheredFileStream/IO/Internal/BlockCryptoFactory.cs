using CipheredFileStream.IO.Exceptions;

namespace CipheredFileStream.IO.Internal;

/// <summary>
/// Concrete <see cref="IBlockCryptoFactory"/> implementation.
/// Serves as the algorithm registry — adding a new algorithm is a new case in the switch.
/// </summary>
internal sealed class BlockCryptoFactory : IBlockCryptoFactory
{
    private readonly byte _defaultAlgorithmId;

    public BlockCryptoFactory(byte defaultAlgorithmId = AesGcmBlockCrypto.AlgorithmIdConst)
    {
        // Validate the default algorithm is known
        _ = GetCiphertextOverhead(defaultAlgorithmId);
        _defaultAlgorithmId = defaultAlgorithmId;
    }

    public byte DefaultAlgorithmId => _defaultAlgorithmId;

    public IBlockCrypto Create(int maxCiphertextSize)
        => CreateForAlgorithm(_defaultAlgorithmId, maxCiphertextSize);

    public IBlockCrypto CreateForAlgorithm(byte algorithmId, int maxCiphertextSize)
    {
        return algorithmId switch
        {
            AesGcmBlockCrypto.AlgorithmIdConst => new AesGcmBlockCrypto(maxCiphertextSize),
            // Future: case 0x02 => new AesCbcHmacBlockCrypto(maxCiphertextSize),
            _ => throw new EncryptedFileCorruptException(
                $"Unknown encryption algorithm 0x{algorithmId:X2}.")
        };
    }

    public int GetCiphertextOverhead(byte algorithmId)
    {
        return algorithmId switch
        {
            AesGcmBlockCrypto.AlgorithmIdConst => AesGcmBlockCrypto.Overhead,
            _ => throw new ArgumentException($"Unknown encryption algorithm 0x{algorithmId:X2}.", nameof(algorithmId))
        };
    }
}
