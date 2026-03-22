using FluentAssertions;
using CipheredFileStream.IO.Internal;

namespace CipheredFileStream.Test.IO;

public class IntegrityTrackerUnitTests
{
    [Fact]
    public void InitialHash_IsAllZeros()
    {
        var tracker = new IntegrityTracker();
        tracker.GetIntegrityHash().Should().BeEquivalentTo(new byte[32]);
    }

    [Fact]
    public void UpdateIntegrity_SingleBlock_HashEqualsTag()
    {
        var tracker = new IntegrityTracker();
        var tag = new byte[32];
        Random.Shared.NextBytes(tag);

        tracker.UpdateIntegrity(0, tag);

        tracker.GetIntegrityHash().Should().BeEquivalentTo(tag);
    }

    [Fact]
    public void UpdateIntegrity_TwoBlocks_HashIsXor()
    {
        var tracker = new IntegrityTracker();
        var tag0 = new byte[32];
        var tag1 = new byte[32];
        Random.Shared.NextBytes(tag0);
        Random.Shared.NextBytes(tag1);

        tracker.UpdateIntegrity(0, tag0);
        tracker.UpdateIntegrity(1, tag1);

        var expected = new byte[32];
        for (int i = 0; i < 32; i++)
            expected[i] = (byte)(tag0[i] ^ tag1[i]);

        tracker.GetIntegrityHash().Should().BeEquivalentTo(expected);
    }

    [Fact]
    public void RecordBlockHash_Then_RemoveBlock_CancelsOut()
    {
        var tracker = new IntegrityTracker();
        var tag = new byte[32];
        Random.Shared.NextBytes(tag);

        tracker.UpdateIntegrity(0, tag);
        // Hash is now equal to tag

        tracker.RemoveBlock(0);
        // Hash should be back to zero

        tracker.GetIntegrityHash().Should().BeEquivalentTo(new byte[32]);
    }

    [Fact]
    public void UpdateIntegrity_ReplacingBlock_XorsCorrectly()
    {
        var tracker = new IntegrityTracker();
        var oldTag = new byte[32];
        var newTag = new byte[32];
        Random.Shared.NextBytes(oldTag);
        Random.Shared.NextBytes(newTag);

        // First write
        tracker.UpdateIntegrity(0, oldTag);
        tracker.GetIntegrityHash().Should().BeEquivalentTo(oldTag);

        // Overwrite same block
        tracker.UpdateIntegrity(0, newTag);
        // Should XOR out old, XOR in new: 0 ^ oldTag ^ oldTag ^ newTag = newTag
        tracker.GetIntegrityHash().Should().BeEquivalentTo(newTag);
    }

    [Fact]
    public void GetIntegrityHash_ReturnsCopy()
    {
        var tracker = new IntegrityTracker();
        var tag = new byte[32];
        Random.Shared.NextBytes(tag);
        tracker.UpdateIntegrity(0, tag);

        var hash1 = tracker.GetIntegrityHash();
        var hash2 = tracker.GetIntegrityHash();

        hash1.Should().BeEquivalentTo(hash2);
        hash1.Should().NotBeSameAs(hash2); // different array instance
    }

    [Fact]
    public void SetIntegrityHash_OverridesValue()
    {
        var tracker = new IntegrityTracker();
        var hash = new byte[32];
        Random.Shared.NextBytes(hash);

        tracker.SetIntegrityHash(hash);
        tracker.GetIntegrityHash().Should().BeEquivalentTo(hash);
    }

    [Fact]
    public void Reset_ClearsEverything()
    {
        var tracker = new IntegrityTracker();
        var tag = new byte[32];
        Random.Shared.NextBytes(tag);
        tracker.UpdateIntegrity(0, tag);

        tracker.Reset();

        tracker.GetIntegrityHash().Should().BeEquivalentTo(new byte[32]);
        tracker.GetCachedBlockHash(0).Should().BeNull();
    }
}
