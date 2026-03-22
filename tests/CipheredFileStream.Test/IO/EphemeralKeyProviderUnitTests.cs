using FluentAssertions;
using CipheredFileStream.IO;

namespace CipheredFileStream.Test.IO;

public class EphemeralKeyProviderUnitTests
{
    [Fact]
    public void GetKey_Returns32Bytes()
    {
        using var provider = new EphemeralKeyProvider();
        var key = provider.GetKey();

        key.Should().NotBeNull();
        key.Length.Should().Be(32);
    }

    [Fact]
    public void GetKey_ReturnsSameInstance()
    {
        using var provider = new EphemeralKeyProvider();
        var key1 = provider.GetKey();
        var key2 = provider.GetKey();

        key1.Should().BeSameAs(key2);
    }

    [Fact]
    public void DifferentProviders_DifferentKeys()
    {
        using var provider1 = new EphemeralKeyProvider();
        using var provider2 = new EphemeralKeyProvider();

        var key1 = provider1.GetKey();
        var key2 = provider2.GetKey();

        key1.Should().NotBeEquivalentTo(key2);
    }

    [Fact]
    public void Dispose_ZerosKey()
    {
        var provider = new EphemeralKeyProvider();
        var key = provider.GetKey();

        key.Any(b => b != 0).Should().BeTrue("key should have non-zero values before dispose");

        provider.Dispose();

        key.All(b => b == 0).Should().BeTrue("key should be zeroed after dispose");
    }

    [Fact]
    public void GetKey_AfterDispose_Throws()
    {
        var provider = new EphemeralKeyProvider();
        provider.Dispose();

        var act = () => provider.GetKey();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var provider = new EphemeralKeyProvider();

        provider.Dispose();
        var act = () => provider.Dispose();
        act.Should().NotThrow();
    }
}
