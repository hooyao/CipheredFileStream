namespace CipheredFileStream.IO.Internal;

internal static class ThrowHelper
{
    public static void ThrowIfNull(object? argument, string paramName)
    {
        if (argument is null)
            throw new ArgumentNullException(paramName);
    }

    public static void ThrowIfNullOrEmpty(string? argument, string paramName)
    {
        if (string.IsNullOrEmpty(argument))
            throw new ArgumentException("Value cannot be null or empty.", paramName);
    }

    public static void ThrowIfDisposed(bool disposed, object instance)
    {
        if (disposed)
            throw new ObjectDisposedException(instance.GetType().FullName);
    }
}
