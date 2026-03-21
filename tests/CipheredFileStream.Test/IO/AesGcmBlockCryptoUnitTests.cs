using System.Security.Cryptography;
using FluentAssertions;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class AesGcmBlockCryptoUnitTests : IDisposable
{
    private readonly AesGcmBlockCrypto _crypto = new();
    private readonly byte[] _key;

    public AesGcmBlockCryptoUnitTests()
    {
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
    }

    [Fact]
    public void AlgorithmId_Is_0x01()
    {
        _crypto.AlgorithmId.Should().Be(0x01);
    }

    [Fact]
    public void CiphertextOverhead_Is_28()
    {
        _crypto.CiphertextOverhead.Should().Be(28);
    }

    [Fact]
    public void IntegrityTagSize_Is_32()
    {
        _crypto.IntegrityTagSize.Should().Be(32);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(16384)]
    public void EncryptDecrypt_RoundTrip(int size)
    {
        var plaintext = new byte[size];
        RandomNumberGenerator.Fill(plaintext);

        var ciphertext = new byte[_crypto.GetCiphertextSize(size)];
        var decrypted = new byte[size];
        var encTag = new byte[32];
        var decTag = new byte[32];
        Span<byte> aad = stackalloc byte[8];
        BitConverter.TryWriteBytes(aad, 42L); // block index 42

        int ctLen = _crypto.Encrypt(_key, plaintext, 0, size, aad, ciphertext, 0, encTag);
        ctLen.Should().Be(size + 28);

        int ptLen = _crypto.Decrypt(_key, ciphertext, 0, ctLen, aad, decrypted, 0, decTag);
        ptLen.Should().Be(size);
        decrypted.Should().BeEquivalentTo(plaintext);
        decTag.Should().BeEquivalentTo(encTag);
    }

    [Fact]
    public void WrongKey_ReturnsNegativeOne()
    {
        var plaintext = new byte[100];
        RandomNumberGenerator.Fill(plaintext);

        var ct = new byte[128];
        var pt = new byte[100];
        var tag = new byte[32];
        Span<byte> aad = stackalloc byte[8];

        _crypto.Encrypt(_key, plaintext, 0, 100, aad, ct, 0, tag);

        var wrongKey = new byte[32];
        RandomNumberGenerator.Fill(wrongKey);

        int result = _crypto.Decrypt(wrongKey, ct, 0, 128, aad, pt, 0, tag);
        result.Should().Be(-1);
    }

    [Fact]
    public void TamperedCiphertext_ReturnsNegativeOne()
    {
        var plaintext = new byte[100];
        var ct = new byte[128];
        var pt = new byte[100];
        var tag = new byte[32];
        Span<byte> aad = stackalloc byte[8];

        _crypto.Encrypt(_key, plaintext, 0, 100, aad, ct, 0, tag);

        // Flip a byte in the middle of ciphertext (after 12B nonce)
        ct[20] ^= 0xFF;

        int result = _crypto.Decrypt(_key, ct, 0, 128, aad, pt, 0, tag);
        result.Should().Be(-1);
    }

    [Fact]
    public void WrongAad_ReturnsNegativeOne()
    {
        var plaintext = new byte[100];
        var ct = new byte[128];
        var pt = new byte[100];
        var tag = new byte[32];
        Span<byte> aad1 = stackalloc byte[8];
        BitConverter.TryWriteBytes(aad1, 1L);
        Span<byte> aad2 = stackalloc byte[8];
        BitConverter.TryWriteBytes(aad2, 2L);

        _crypto.Encrypt(_key, plaintext, 0, 100, aad1, ct, 0, tag);

        int result = _crypto.Decrypt(_key, ct, 0, 128, aad2, pt, 0, tag);
        result.Should().Be(-1);
    }

    [Fact]
    public void IntegrityTag_Has_GcmTag_ZeroPadded()
    {
        var plaintext = new byte[100];
        var ct = new byte[128];
        var tag = new byte[32];
        Span<byte> aad = stackalloc byte[8];

        _crypto.Encrypt(_key, plaintext, 0, 100, aad, ct, 0, tag);

        // First 16 bytes should be non-zero (GCM tag)
        tag.AsSpan(0, 16).ToArray().Should().NotBeEquivalentTo(new byte[16]);
        // Last 16 bytes should be zero (padding)
        tag.AsSpan(16, 16).ToArray().Should().BeEquivalentTo(new byte[16]);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(1000)]
    [InlineData(16384)]
    public void GetCiphertextSize_And_GetMaxPlaintextSize_AreInverse(int size)
    {
        int ctSize = _crypto.GetCiphertextSize(size);
        int ptSize = _crypto.GetMaxPlaintextSize(ctSize);
        ptSize.Should().Be(size);
    }

    public void Dispose() => _crypto.Dispose();
}
