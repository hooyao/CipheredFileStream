# CipheredFileStream

[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()

Drop-in `System.IO.Stream` replacement with transparent AES-GCM block-level encryption, pluggable algorithm architecture, and hardware-accelerated performance.

## Features

- **Transparent encryption** -- reads and writes through a standard `Stream` interface
- **AES-256-GCM** with hardware acceleration (AES-NI + PCLMULQDQ)
- **Pluggable crypto** via `IBlockCrypto` / `IBlockCryptoFactory` -- adding a new algorithm is one class + one switch case
- **Configurable block sizes** from 4 KB to 128 KB (default 16 KB)
- **Two access patterns**: Sequential (ring buffers, parallel crypto) and RandomAccess (single-block cache)
- **PBKDF2-SHA256** password-based key derivation (configurable iterations, default 600K)
- **File-level integrity** via XOR of per-block GCM authentication tags
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

## Performance

Sequential access pattern, measured on hardware with AES-NI support.

<details>
<summary>Throughput by block size</summary>

| Block Size | Write (MB/s) | Read (MB/s) |
|:----------:|:------------:|:-----------:|
| 4 KB       | 382          | 1,843       |
| 8 KB       | 770          | 2,701       |
| 16 KB      | 1,139        | 3,067       |
| 32 KB      | 1,672        | 2,600       |
| 64 KB      | 2,072        | 3,147       |
| 128 KB     | 2,361        | 3,135       |

</details>

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
