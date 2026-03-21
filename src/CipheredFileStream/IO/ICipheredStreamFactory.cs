namespace CipheredFileStream.IO;

public interface ICipheredStreamFactory : IDisposable
{
    Stream Create(string path, FileMode mode, CipheredFileStreamOptions? options = null);
    Stream Create(string path, FileMode mode, FileAccess access, CipheredFileStreamOptions? options = null);
    Stream Create(string path, FileMode mode, FileAccess access, FileShare share, CipheredFileStreamOptions? options = null);
}
