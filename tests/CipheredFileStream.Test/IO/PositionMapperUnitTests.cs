using FluentAssertions;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class PositionMapperUnitTests
{
    private const int GcmOverhead = 28;

    private static PositionMapper CreateMapper(int exponent = 14)
    {
        var layout = new BlockLayout(exponent, GcmOverhead);
        return new PositionMapper(layout);
    }

    [Fact]
    public void Position0_MapsTo_Block0_WithDataStart()
    {
        var mapper = CreateMapper();
        var (blockIndex, offset) = mapper.MapPosition(0);
        blockIndex.Should().Be(0);
        offset.Should().Be(87); // Block0DataStart
    }

    [Fact]
    public void Position_AtBlock0Boundary_MapsTo_Block1()
    {
        var mapper = CreateMapper();
        var layout = new BlockLayout(14, GcmOverhead);
        long boundary = layout.Block0DataCapacity;

        var (blockIndex, offset) = mapper.MapPosition(boundary);
        blockIndex.Should().Be(1);
        offset.Should().Be(0);
    }

    [Fact]
    public void Position_InMiddleOfBlock1_MapsCorrectly()
    {
        var mapper = CreateMapper();
        var layout = new BlockLayout(14, GcmOverhead);
        long pos = layout.Block0DataCapacity + 100;

        var (blockIndex, offset) = mapper.MapPosition(pos);
        blockIndex.Should().Be(1);
        offset.Should().Be(100);
    }

    [Fact]
    public void GetBlockCount_ZeroLength_ReturnsZero()
    {
        var mapper = CreateMapper();
        mapper.GetBlockCount(0).Should().Be(0);
    }

    [Fact]
    public void GetBlockCount_SmallFile_ReturnsOne()
    {
        var mapper = CreateMapper();
        mapper.GetBlockCount(1).Should().Be(1);
        mapper.GetBlockCount(100).Should().Be(1);
    }

    [Fact]
    public void GetBlockCount_ExactlyBlock0Capacity_ReturnsOne()
    {
        var mapper = CreateMapper();
        var layout = new BlockLayout(14, GcmOverhead);
        mapper.GetBlockCount(layout.Block0DataCapacity).Should().Be(1);
    }

    [Fact]
    public void GetBlockCount_OneByteOverBlock0_ReturnsTwo()
    {
        var mapper = CreateMapper();
        var layout = new BlockLayout(14, GcmOverhead);
        mapper.GetBlockCount(layout.Block0DataCapacity + 1).Should().Be(2);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(14)]
    [InlineData(17)]
    public void GetCleartextPositionForBlock_RoundTrips(int exponent)
    {
        var mapper = CreateMapper(exponent);
        var layout = new BlockLayout(exponent, GcmOverhead);

        // Block 0 starts at cleartext 0
        mapper.GetCleartextPositionForBlock(0).Should().Be(0);

        // Block 1 starts at Block0DataCapacity
        mapper.GetCleartextPositionForBlock(1).Should().Be(layout.Block0DataCapacity);

        // Block 2 = Block0DataCapacity + BlockNDataCapacity
        mapper.GetCleartextPositionForBlock(2).Should().Be(
            layout.Block0DataCapacity + layout.BlockNDataCapacity);
    }

    [Fact]
    public void GetBlockDataCapacity_Block0_IsSmaller()
    {
        var mapper = CreateMapper();
        var layout = new BlockLayout(14, GcmOverhead);
        mapper.GetBlockDataCapacity(0).Should().Be(layout.Block0DataCapacity);
        mapper.GetBlockDataCapacity(1).Should().Be(layout.BlockNDataCapacity);
        mapper.GetBlockDataCapacity(0).Should().BeLessThan(mapper.GetBlockDataCapacity(1));
    }

    [Fact]
    public void MapPosition_LastByteOfBlock0()
    {
        var layout = new BlockLayout(14, GcmOverhead);
        var mapper = CreateMapper();
        long position = layout.Block0DataCapacity - 1;

        var (blockIndex, offset) = mapper.MapPosition(position);

        blockIndex.Should().Be(0);
        offset.Should().Be(layout.Block0DataStart + layout.Block0DataCapacity - 1);
    }

    [Fact]
    public void MapPosition_LargePosition_Block5()
    {
        var layout = new BlockLayout(14, GcmOverhead);
        var mapper = CreateMapper();
        long position = layout.Block0DataCapacity + (long)layout.BlockNDataCapacity * 4 + 42;

        var (blockIndex, offset) = mapper.MapPosition(position);

        blockIndex.Should().Be(5);
        offset.Should().Be(42);
    }

    [Fact]
    public void GetBlockDataCapacity_BlockN()
    {
        var layout = new BlockLayout(14, GcmOverhead);
        var mapper = CreateMapper();

        mapper.GetBlockDataCapacity(1).Should().Be(layout.BlockNDataCapacity);
        mapper.GetBlockDataCapacity(2).Should().Be(layout.BlockNDataCapacity);
        mapper.GetBlockDataCapacity(3).Should().Be(layout.BlockNDataCapacity);
    }

    [Fact]
    public void GetPhysicalOffset_ReturnsCorrectOffsets()
    {
        var layout = new BlockLayout(14, GcmOverhead);
        var mapper = CreateMapper();

        mapper.GetPhysicalOffset(0).Should().Be(0);
        mapper.GetPhysicalOffset(1).Should().Be(layout.BlockSize);
        mapper.GetPhysicalOffset(2).Should().Be((long)layout.BlockSize * 2);
    }

    [Fact]
    public void MapPosition_ConsecutiveBytes_AcrossBoundary()
    {
        var layout = new BlockLayout(14, GcmOverhead);
        var mapper = CreateMapper();

        var (blockA, offsetA) = mapper.MapPosition(layout.Block0DataCapacity - 1);
        var (blockB, offsetB) = mapper.MapPosition(layout.Block0DataCapacity);

        blockA.Should().Be(0);
        blockB.Should().Be(1);
        blockA.Should().NotBe(blockB);
        offsetA.Should().Be(layout.Block0DataStart + layout.Block0DataCapacity - 1);
        offsetB.Should().Be(0);
    }
}
