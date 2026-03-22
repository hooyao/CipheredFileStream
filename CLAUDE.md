# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build
dotnet build src/CipheredFileStream/CipheredFileStream.csproj

# Run all tests (set CFS_TEST_TEMP to a drive with space if system temp is limited)
CFS_TEST_TEMP="Z:" dotnet test tests/CipheredFileStream.Test/

# Run functional tests only (skip perf/endurance, ~90 seconds)
dotnet test tests/CipheredFileStream.Test/ --filter "Category!=Performance&Category!=Benchmark&Category!=Profiling&Category!=Endurance"

# Run a single test class
dotnet test tests/CipheredFileStream.Test/ --filter "FullyQualifiedName~BasicRoundTripTests"

# Run a single test method across all block sizes
dotnet test tests/CipheredFileStream.Test/ --filter "FullyQualifiedName~Parity01_Write_Flush_Write_Flush"

# See ITestOutputHelper output (throughput numbers, etc.)
dotnet test tests/CipheredFileStream.Test/ --logger "console;verbosity=detailed" --filter "FullyQualifiedName~SequentialWriteRead"
```

## Architecture

### Pluggable Block-Level Encryption

The library provides a `System.IO.Stream` drop-in replacement that transparently encrypts/decrypts data in fixed-size blocks. The encryption algorithm is pluggable via `IBlockCrypto`/`IBlockCryptoFactory`. Currently only AES-256-GCM is implemented (AlgorithmId `0x01`).

**To add a new algorithm:** Create a class implementing `IBlockCrypto` in `IO/Internal/`, add a case to `BlockCryptoFactory`, add a value to the `EncryptionAlgorithm` enum. No file format version change needed — only the algorithm ID byte in the header changes.

### File Format (v3)

32-byte fixed cleartext header (unencrypted, readable without key):
```
[2B magic "BC"][2B version 0x0003][1B blockSizeExp][1B algorithmId]
[1B kdfMethod][1B reserved][16B salt][4B iterations][4B reserved]
```

Block layout on disk:
- Block 0: `[32B header][4B ciphertext length][ciphertext][padding to block size]`
- Block N: `[4B ciphertext length][ciphertext][padding to block size]`
- Block 0 payload (decrypted): `[2B protobuf header length][85B protobuf region][user data]`

### IO Paths

Two access patterns with automatic fallback:

- **Sequential** (default): `WriteBehindBuffer` accumulates writes, bulk-encrypts in parallel, writes in one syscall. `ReadAheadBuffer` bulk-reads and parallel-decrypts. Ring buffer slots sized to `BufferSize / BlockSize`.
- **RandomAccess**: `BlockManager` single-block cache. Loads one block at a time, writes back when dirty.

**Fallback rules** (once triggered, permanent for stream lifetime):
- Write at position != EOF (overwrite) → fallback to BlockManager
- `SetLength` → fallback to BlockManager
- Seek/Position change with pending write data → flushes WriteBehindBuffer (but does NOT permanently fallback; ring buffers resume)

### Key Components (`IO/Internal/`)

| Component | Role |
|-----------|------|
| `CipheredFileStream` | Main `Stream` facade. Routes to sequential buffers or BlockManager. |
| `BlockManager` | Single-block cache. Loads/decrypts/encrypts one block. Used by RandomAccess and fallback. |
| `ReadAheadBuffer` | Bulk-reads N blocks → parallel decrypt → serves from decrypted slots. |
| `WriteBehindBuffer` | Accumulates plaintext → parallel encrypt → bulk write. Append-only. |
| `IBlockCrypto` | Pluggable crypto. Encrypt/Decrypt produce separate 32-byte integrity tags. |
| `BlockLayout` | Computes PayloadCapacity from block size exponent + algorithm overhead. |
| `IntegrityTracker` | XOR of per-block integrity tags. Algorithm-agnostic (receives tags, never parses ciphertext). |
| `PositionMapper` | Maps cleartext position → (blockIndex, offsetInPayload). |

### Public API (`IO/`)

| Type | Purpose |
|------|---------|
| `ICipheredStreamFactory` / `CipheredFileStreamFactory` | Creates encrypted streams. Static `ReadFileHeader()` inspects header without key. |
| `IKeyProvider` / `EphemeralKeyProvider` / `PasswordKeyProvider` | Key management. PBKDF2-SHA256 with configurable iterations. |
| `CipheredFileStreamOptions` | BlockSize, AccessPattern, BufferSize, ConcurrencyLevel, Algorithm. |
| `FileHeaderInfo` | Readonly struct from `ReadFileHeader()` — KdfMethod, Salt, Iterations, AlgorithmId. |

### Namespace Collision

`CipheredFileStream` is both a root namespace and an internal class name. When referencing the class from `CipheredFileStream.IO` namespace (e.g., in the factory), use `Internal.CipheredFileStream`.

## Testing Patterns

- **1814 tests total**, 1565 functional + perf/endurance/benchmark
- Almost all IO tests are `[Theory]` × `AllBlockSizes` (6 sizes: 4K–128K), multiplying method count by 6
- `CryptoTestBase`: shared base class providing `_factory`, `_key`, `GetTestFilePath()`, `AllBlockSizes`
- Temp directory controlled by `CFS_TEST_TEMP` env var (defaults to system temp)
- **FileStream parity tests** (`OperationSequenceParityTests`): mirror every operation on both CipheredFileStream and plain FileStream, then compare SHA-256 of reopened contents — the gold standard for correctness
- `TortureTestBudget`: xUnit collection fixture for endurance tests, auto-detects disk budget
- Test categories: `Performance`, `Benchmark`, `Profiling`, `Endurance` (filtered out by default in fast runs)
- `BlockLayout` constructor requires TWO args: `new BlockLayout((int)blockSize, 28)` where 28 is `AesGcmBlockCrypto.Overhead`

## Known Gotchas

- `PayloadCapacity` is constrained by Block0 (which has 32B less space than BlockN due to cleartext header). For algorithms without padding (like GCM), this matters — computed from `Block0MaxCiphertextSize`, not `BlockNMaxCiphertextSize`.
- `WriteBehindBuffer.InitializeSlot()` zeros the slot. After a Flush, if the next append write lands mid-block, `IsMidBlockAppend()` detects this and falls back to BlockManager to avoid overwriting existing block data.
- `Seek()` and `Position` setter both flush pending WriteBehindBuffer data. Without this, write→seek→read loses unflushed data.
- `WriteHeader()` always rewrites the 32-byte cleartext header (not just on first create). This prevents the header from being lost after `SetLength(0)`.

## Reference Implementation

`MMP.Core.Crypto/` contains a reference implementation using AES-256-CBC+HMAC-SHA512 (R9 scheme). It cannot be built standalone (depends on internal NuGet packages). Use it only as an architectural reference — our implementation is not byte-compatible with MMP files.
