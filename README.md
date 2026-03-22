# CipheredFileStream

[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()

**Block-based encrypted file stream for .NET with full random read/write support.**

Unlike whole-file encryption (where you must decrypt everything, modify, then re-encrypt the entire file), CipheredFileStream encrypts data in independent fixed-size blocks. This means you can seek to any position and read or write just the blocks you need — the rest of the file stays untouched on disk. This makes it practical for large files, databases, logs, or any scenario where you need encrypted storage with random access.

## Features

- **Block-level encryption** -- each block encrypted independently; read/write any part without touching the rest
- **Full random access** -- seek, overwrite, and read at arbitrary positions, just like a regular `FileStream`
- **Drop-in `Stream` replacement** -- standard `System.IO.Stream` interface, works with any code that uses streams
- **AES-256-GCM** with hardware acceleration (AES-NI + PCLMULQDQ)
- **Pluggable crypto** via `IBlockCrypto` / `IBlockCryptoFactory` -- adding a new algorithm is one class + one switch case
- **Configurable block sizes** from 4 KB to 128 KB (default 16 KB)
- **Two access patterns**: Sequential (ring buffers, parallel crypto) and RandomAccess (single-block cache), with automatic fallback
- **PBKDF2-SHA256** password-based key derivation (configurable iterations, default 600K)
- **Per-block integrity** via GCM authentication tags + XOR-based file-level integrity tracking
- **Block reordering detection** via AAD binding (block index as authenticated data)
- **Key material zeroed on dispose**

## Quick Start

### Direct key

```csharp
byte[] key = RandomNumberGenerator.GetBytes(32);
using var factory = new CipheredFileStreamFactory(key);
using Stream stream = factory.Create("data.enc", FileMode.Create);
stream.Write(data, 0, data.Length);
```

### Password-based

```csharp
using var provider = new PasswordKeyProvider("mypassword");
using var factory = new CipheredFileStreamFactory(provider);
using Stream stream = factory.Create("secure.enc", FileMode.Create);
```

### Open existing file

```csharp
var info = CipheredFileStreamFactory.ReadFileHeader("secure.enc");
if (info.KdfMethod == KdfMethod.Pbkdf2Sha256)
{
    using var provider = new PasswordKeyProvider("mypassword", info.Salt!, info.KdfIterations);
    using var factory = new CipheredFileStreamFactory(provider);
    using Stream stream = factory.Create("secure.enc", FileMode.Open, FileAccess.Read);
}
```

### Options

```csharp
var options = new CipheredFileStreamOptions
{
    BlockSize = BlockSizeOption.Block32K,
    AccessPattern = AccessPattern.Sequential,
    BufferSize = 2 * 1024 * 1024, // 2 MB ring buffer
    ConcurrencyLevel = 4,
};
```

### Random access

```csharp
var options = new CipheredFileStreamOptions { AccessPattern = AccessPattern.RandomAccess };
using var factory = new CipheredFileStreamFactory(key, options);
using Stream stream = factory.Create("data.enc", FileMode.Open, FileAccess.ReadWrite);

// Seek to any position and read/write — only the affected block(s) are decrypted/encrypted
stream.Position = 1_000_000;
stream.Write(patch, 0, patch.Length);

stream.Position = 500_000;
stream.Read(buffer, 0, buffer.Length);
```

## Performance

Measured on hardware with AES-NI support, 256 MB payload, default 16 KB block size.

### Sequential throughput (ring buffers + parallel crypto)

| Block Size | Write (MB/s) | Read (MB/s) |
|:----------:|:------------:|:-----------:|
| 4 KB       | 321          | 1,190       |
| 8 KB       | 555          | 1,860       |
| 16 KB      | 837          | 2,271       |
| 32 KB      | 1,089        | 2,437       |
| 64 KB      | 1,135        | 2,462       |
| 128 KB     | 1,243        | 2,293       |

### Random access (single-block cache)

| Workload                       | Result         |
|:-------------------------------|:--------------:|
| Random 4 KB read (10K ops)     | 56,231 IOPS    |
| Random 4 KB write (10K ops)    | 26,359 IOPS    |
| Mixed 70/30 read/write (10K ops) | 38,409 IOPS |
| Block thrashing (alternating)  | 66,211 IOPS    |
| Avg random read latency        | 17.8 μs        |

### Sequential vs RandomAccess read comparison

| Block Size | Sequential (MB/s) | RandomAccess (MB/s) | Ratio |
|:----------:|:------------------:|:-------------------:|:-----:|
| 4 KB       | 1,382              | 551                 | 2.51x |
| 8 KB       | 1,840              | 894                 | 2.06x |
| 16 KB      | 1,974              | 1,361               | 1.45x |
| 32 KB      | 2,106              | 1,574               | 1.34x |
| 64 KB      | 1,932              | 1,922               | 1.01x |
| 128 KB     | 1,966              | 1,854               | 1.06x |

> With large block sizes, random access reads approach sequential speed since each block read amortizes the syscall overhead.

## File Format (v3)

32-byte cleartext header followed by encrypted blocks:

```
┌─────────────────── Cleartext Header (32 bytes) ───────────────────┐
│ Magic  │ Ver  │ BSE │ Alg │ KDF │ Rsv │   Salt (16B)  │Iter│Rsv │
│ 2B     │ 2B   │ 1B  │ 1B  │ 1B  │ 1B  │    16 bytes   │ 4B │ 4B │
└───────────────────────────────────────────────────────────────────┘

┌─────────────── Encrypted Block ───────────────┐
│ CiphertextLen (4B) │ Nonce (12B) │ Ciphertext │ Tag (16B) │
└───────────────────────────────────────────────┘
```

- **BSE** -- Block Size Exponent (12-17, i.e. 4 KB - 128 KB)
- **Alg** -- Algorithm ID (`0x01` = AES-256-GCM)
- **KDF** -- Key derivation method (`0x00` = none, `0x01` = PBKDF2-SHA256)
- **AAD** per block -- 8-byte block index (little-endian), binds each block to its position

New encryption algorithms do not require a file format version change -- only a new `Alg` byte value.

## Architecture

```
CipheredFileStreamFactory
  └─ CipheredFileStream : Stream
       ├─ PositionMapper         (logical ↔ physical offset translation)
       ├─ BlockLayout             (block geometry calculations)
       ├─ IntegrityTracker        (XOR of per-block GCM tags)
       ├─ BlockCryptoFactory → IBlockCrypto  (pluggable encryption)
       └─ Access pattern:
            ├─ ReadAheadBuffer    (sequential read, ring buffer, parallel decrypt)
            ├─ WriteBehindBuffer  (sequential write, ring buffer, parallel encrypt)
            └─ BlockManager       (random access, single-block cache)
```

## Adding a New Algorithm

1. Implement `IBlockCrypto`
2. Add a case to `BlockCryptoFactory`
3. Add a value to the `EncryptionAlgorithm` enum
4. No file format version change needed

## Security

- AES-256-GCM with hardware acceleration (AES-NI + PCLMULQDQ)
- Per-block random 12-byte nonce
- Block index as AAD prevents block reordering/swapping
- PBKDF2-SHA256 with configurable iterations (default 600,000)
- All key material zeroed on dispose
- **Not thread-safe** (same contract as `FileStream`)

## Building

```bash
dotnet build src/CipheredFileStream/
dotnet test tests/CipheredFileStream.Test/
```

## Testing

- **1,814 tests** total
- Parameterized across all 6 block sizes (4 KB - 128 KB)
- `FileStream` parity tests: every operation mirrored against `FileStream` with SHA-256 comparison
- Performance benchmarks, endurance stress tests, and profiling harnesses

## License

[MIT](LICENSE)
