# AGENTS.md - CipheredFileStream

## Project Overview

CipheredFileStream is a .NET 10 C# library that provides an encrypted file stream implementation. Files are encrypted using AES-GCM and stored on disk in configurable chunks (4K/8K/16K/32K/64K/128K) for efficient random access. The file format uses Protobuf for headers and includes a magic number for format identification with built-in authentication (tamper detection).

## Project Structure

```
CipheredFileStream/
├── doc/                             # Design documents
│   └── technical-design.md          # Technical design spec
├── src/
│   └── CipheredFileStream/         # Main library project (net10.0)
├── tests/
│   └── CipheredFileStream.Tests/   # xUnit test project (net10.0)
└── CipheredFileStream.sln
```

## Build Commands

```bash
# Build entire solution
dotnet build

# Build specific project
dotnet build src/CipheredFileStream/CipheredFileStream.csproj

# Build in Release mode
dotnet build -c Release

# Restore NuGet packages
dotnet restore
```

## Test Commands

```bash
# Run all tests
dotnet test

# Run tests with verbose output
dotnet test --verbosity normal

# Run a single test by name
dotnet test --filter "FullyQualifiedName~ClassName.MethodName"

# Run tests in a specific class
dotnet test --filter "ClassName=ClassNameHere"

# Run tests matching a pattern
dotnet test --filter "Name~Ciphered"

# Run tests with code coverage
dotnet test --collect:"XPlat Code Coverage"
```

## Lint & Format Commands

```bash
# Format code (uses .editorconfig)
dotnet format

# Format and verify (CI mode)
dotnet format --verify-no-changes

# Analyze code for issues
dotnet build --warnaserror
```

## Code Style Guidelines

### Imports & Namespaces

- Use file-scoped namespace declarations: `namespace CipheredFileStream;`
- Place `System.*` namespaces first, then third-party, then project namespaces
- Remove unused imports; rely on ImplicitUsings (enabled by default)
- Prefer `using` statements at file top, not inside namespace

### Types & Naming

- PascalCase: classes, methods, properties, public fields, constants
- camelCase: local variables, parameters, private fields
- _camelCase: private fields (underscore prefix)
- Interfaces: prefix with `I` (e.g., `ICipheredStream`)
- Use `record` types for immutable data (headers, configs)
- Use `Span<T>` / `Memory<T>` for high-performance buffer operations

### Nullability & Safety

- Nullable reference types are enabled project-wide
- Always handle nullable warnings; do not suppress with `!`
- Use `ArgumentNullException.ThrowIfNull()` for parameter validation
- Prefer `string.IsNullOrEmpty()` / `string.IsNullOrWhiteSpace()` checks

### Error Handling

- Throw specific exceptions (`ArgumentException`, `InvalidOperationException`)
- Use `ObjectDisposedException` after disposal checks
- Validate state before operations; fail fast with clear messages
- Use `ThrowHelper` patterns for hot paths (avoid exception allocation overhead)

### Patterns & Practices

- Implement `IDisposable` / `IAsyncDisposable` for resource management
- Use `sealed` classes unless inheritance is explicitly designed
- Prefer composition over inheritance
- Use `ReadOnlySpan<byte>` / `ReadOnlyMemory<byte>` for cryptographic operations
- Avoid allocations in hot paths; use stackalloc, ArrayPool, object pooling
- Use `ConfigureAwait(false)` in library code where applicable
- Cryptographic operations: use `System.Security.Cryptography` (AES-GCM)

### File Format Conventions

- Magic number: first bytes identify CipheredFileStream format
- Header: Protobuf-serialized, follows magic number
- Chunks: configurable size (4K/8K/16K/32K/64K/128K)
- Each chunk encrypted with AES-GCM providing authentication tag
- Chunk size chosen to balance random access performance and encryption overhead

### Testing

- Use xUnit with `[Fact]` for single tests, `[Theory]` with `[InlineData]` / `[MemberData]` for parameterized tests
- Test file: mirror source structure (e.g., `CipheredFileStreamTests.cs`)
- Use `IDisposable` or `IAsyncLifetime` for test resource cleanup
- Use temporary directories for file-based tests; clean up after
- Test both success and failure paths
- Test tamper detection by modifying encrypted chunk bytes

### Documentation

- XML doc comments on all public APIs
- Use `<summary>`, `<param>`, `<returns>`, `<exception>` tags
- Document thread-safety guarantees
- Document disposal behavior
