using FluentAssertions;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class BlockLayoutUnitTests
{
    private const int GcmOverhead = 28; // AesGcmBlockCrypto.Overhead

    [Theory]
    [InlineData(12, 4096)]   // 4K
    [InlineData(13, 8192)]   // 8K
    [InlineData(14, 16384)]  // 16K
    [InlineData(15, 32768)]  // 32K
    [InlineData(16, 65536)]  // 64K
    [InlineData(17, 131072)] // 128K
    public void BlockSize_MatchesExponent(int exponent, int expectedSize)
    {
        var layout = new BlockLayout(exponent, GcmOverhead);
        layout.BlockSize.Should().Be(expectedSize);
        layout.BlockSizeExponent.Should().Be(exponent);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(14)]
    [InlineData(17)]
    public void PayloadCapacity_Equals_Block0MaxCT_Minus_Overhead(int exponent)
    {
        var layout = new BlockLayout(exponent, GcmOverhead);
        // BlockNMaxCiphertextSize = BlockSize - 4 (length prefix)
        layout.BlockNMaxCiphertextSize.Should().Be(layout.BlockSize - 4);
        // Block0MaxCT = BlockSize - 32 (header) - 4 (length prefix)
        layout.Block0MaxCiphertextSize.Should().Be(layout.BlockSize - 32 - 4);
        // PayloadCapacity = Block0MaxCT - overhead (constrained by block 0)
        layout.PayloadCapacity.Should().Be(layout.Block0MaxCiphertextSize - GcmOverhead);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(14)]
    [InlineData(17)]
    public void Block0DataCapacity_Is_PayloadCapacity_Minus_87(int exponent)
    {
        var layout = new BlockLayout(exponent, GcmOverhead);
        layout.Block0DataStart.Should().Be(2 + 85); // HeaderLenPrefix + ProtobufMax = 87
        layout.Block0DataCapacity.Should().Be(layout.PayloadCapacity - 87);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(14)]
    [InlineData(17)]
    public void BlockNDataCapacity_Equals_PayloadCapacity(int exponent)
    {
        var layout = new BlockLayout(exponent, GcmOverhead);
        layout.BlockNDataCapacity.Should().Be(layout.PayloadCapacity);
    }

    [Fact]
    public void Block0MaxCT_Accounts_For_32B_Header()
    {
        var layout = new BlockLayout(14, GcmOverhead); // 16K
        // Block0MaxCT = BlockSize - CleartextHeaderSize(32) - LengthPrefix(4)
        layout.Block0MaxCiphertextSize.Should().Be(16384 - 32 - 4);
    }

    [Theory]
    [InlineData(11)]  // too small
    [InlineData(18)]  // too large
    [InlineData(-1)]
    [InlineData(100)]
    public void InvalidExponent_Throws(int exponent)
    {
        var act = () => new BlockLayout(exponent, GcmOverhead);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Default16K_PayloadCapacity_Is_16320()
    {
        // 16K: Block0MaxCT = 16384 - 32 - 4 = 16348; Payload = 16348 - 28 = 16320
        var layout = new BlockLayout(14, GcmOverhead);
        layout.PayloadCapacity.Should().Be(16320);
    }
}
