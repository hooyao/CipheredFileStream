# CipheredFileStream -- Technical Design Document

**Format version:** v3 (`0x0003`)
**Document revision:** 2.0
**Status:** Current implementation

---

## Table of Contents

1. [Overview](#1-overview)
2. [File Format (v3)](#2-file-format-v3)
3. [Cryptography](#3-cryptography)
4. [Block Layout and Geometry](#4-block-layout-and-geometry)
5. [IO Architecture](#5-io-architecture)
6. [Key Management](#6-key-management)
7. [Public API](#7-public-api)
8. [Security Properties](#8-security-properties)
9. [Performance](#9-performance)
10. [Error Handling](#10-error-handling)
11. [Extensibility](#11-extensibility)

---

## 1. Overview

CipheredFileStream is a .NET `Stream` implementation that provides transparent
block-level AES-256-GCM encryption for files. It serves as a drop-in replacement
for `FileStream`; any code that operates on `Stream` works unchanged.

### Design goals

- **Drop-in Stream replacement** -- standard `Read`/`Write`/`Seek`/`SetLength`
  semantics; no API leakage of encryption details.
- **Block-level authenticated encryption** -- every block is independently
  encrypted and authenticated with AES-GCM, including AAD binding to prevent
  block reordering.
- **File-level integrity** -- XOR of per-block GCM authentication tags provides
  a lightweight file-wide integrity check.
- **High throughput** -- parallel encrypt/decrypt with bulk IO via
  WriteBehindBuffer and ReadAheadBuffer in sequential mode.
- **Pluggable algorithms** -- new ciphers require only a new `IBlockCrypto`
  implementation and a one-byte algorithm ID; the file format, block layout, and
  IO pipeline are algorithm-agnostic.
- **Secure key handling** -- all key material is defensively copied and zeroed on
  dispose.

---

## 2. File Format (v3)

### 2.1 Cleartext Header (32 bytes, fixed, unencrypted)

The first 32 bytes of every file are always in the clear. They allow file
identification, algorithm detection, and KDF parameter retrieval before any
key material is needed.

```
Offset  Size  Field            Encoding         Values / Notes
------  ----  ---------------  ---------------  ---------------------------------
 0       2B   Magic            uint16 LE        0x4342 ("BC")
 2       2B   FormatVersion    uint16 LE        0x0003
 4       1B   BlockSizeExp     uint8            12..17 (4 KB .. 128 KB)
 5       1B   AlgorithmId      uint8            0x01 = AES-256-GCM
 6       1B   KdfMethod        uint8            0x00 = None, 0x01 = PBKDF2-SHA256
 7       1B   Reserved         ---              0x00
 8      16B   Salt             bytes            PBKDF2 salt (zeros when KdfMethod=None)
24       4B   KdfIterations    uint32 LE        PBKDF2 iterations (0 when KdfMethod=None)
28       4B   Reserved         ---              0x00000000
```

Total: **32 bytes**, always at file offset 0.

### 2.2 Physical Block Layout

All blocks have the same physical size (`BlockSize = 1 << BlockSizeExponent`).
Block 0 shares space with the cleartext header; blocks N>=1 use the full block.

```
FILE ON DISK
+==========+============+=====+============+
| Block 0  |  Block 1   | ... |  Block N   |
+==========+============+=====+============+
<--BS-----> <---BS-----> ...   <---BS------>

BS = BlockSize (power of 2, 4 KB to 128 KB)
```

#### Block 0

```
BLOCK 0 (BlockSize bytes)
+--------------------+------------+----------------------------+----------+
| Cleartext Header   | CT Length  |        Ciphertext          | Padding  |
|     32 bytes       |  4 bytes   |   (encrypted envelope)     | (zeros)  |
|   UNENCRYPTED      | uint32 LE  |                            |          |
+--------------------+------------+----------------------------+----------+
|<-- offset 0 ------>|<- 32 ----->|<-- 36 .. 36+ctLen-1 ----->|<- to BS->|
```

#### Block N (N >= 1)

```
BLOCK N (BlockSize bytes)
+------------+--------------------------------------+--------------------+
| CT Length  |             Ciphertext               |      Padding       |
|  4 bytes   |       (encrypted envelope)           |      (zeros)       |
| uint32 LE  |                                      |                    |
+------------+--------------------------------------+--------------------+
|<- 0..3 --->|<---- 4 .. 4+ctLen-1 --------------->|<-- to BlockSize -->|
```

### 2.3 Ciphertext Envelope (AES-GCM)

Each ciphertext region contains the full AEAD envelope:

```
CIPHERTEXT ENVELOPE
+----------+--------------------+----------+
|  Nonce   |    Ciphertext      | Auth Tag |
| 12 bytes |  (plaintext size)  | 16 bytes |
+----------+--------------------+----------+

Total overhead: 28 bytes per block (12 + 16)
```

### 2.4 Block 0 Decrypted Payload

After decryption, the block 0 payload contains embedded file metadata followed
by user data:

```
BLOCK 0 -- DECRYPTED PAYLOAD (PayloadCapacity bytes)
+----------+-----------------------------+-------------------------------+
| Hdr Len  | Protobuf Header (reserved)  |          User Data            |
| 2 bytes  |       85 bytes max          |                               |
| uint16LE |                             |                               |
+----------+-----------------------------+-------------------------------+
|<- 0..1 ->|<------ 2 .. 86 ----------->|<- 87 .. PayloadCapacity-1 --->|
```

- **Header length prefix** (2 bytes): actual serialized Protobuf length.
- **Protobuf region** (85 bytes max): reserved space so that user data always
  starts at a fixed offset (87) regardless of actual Protobuf serialization size.
- **User data**: starts at byte 87, capacity = `PayloadCapacity - 87`.

### 2.5 Protobuf Header Schema

```protobuf
syntax = "proto3";
package CipheredFileStream;

message EncryptedFileHeader {
    sfixed64 cleartext_length  = 1;  // logical file size in bytes
    bytes    integrity_hash    = 2;  // XOR of per-block GCM tags (32 bytes)
    sfixed32 block_count       = 3;  // total physical block count
    sfixed32 header_version    = 4;  // header schema version (currently 1)
}
```

Fixed-size types (`sfixed64`, `sfixed32`) are used for predictable serialized
size. Maximum serialized size: 53 bytes (well within the 85-byte reservation).

| Field              | Tag + Data  | Purpose                          |
|--------------------|-------------|----------------------------------|
| `cleartext_length` | 1 + 8 = 9B | Logical plaintext file size      |
| `integrity_hash`   | 1+1+32=34B  | File-wide integrity checksum     |
| `block_count`      | 1 + 4 = 5B  | Number of physical blocks        |
| `header_version`   | 1 + 4 = 5B  | Schema version for future compat |
| **Total max**      | **53 bytes**|                                  |

---

## 3. Cryptography

### 3.1 AES-256-GCM (AlgorithmId 0x01)

| Parameter          | Value                                |
|--------------------|--------------------------------------|
| Cipher             | AES-256-GCM (Galois/Counter Mode)    |
| Key size           | 256 bits (32 bytes)                  |
| Nonce size         | 96 bits (12 bytes), random per block |
| Auth tag size      | 128 bits (16 bytes)                  |
| Ciphertext overhead| 28 bytes (12 nonce + 16 tag)         |
| Padding            | None (CTR mode)                      |
| HW acceleration    | AES-NI + PCLMULQDQ (GHASH)          |

Each block encryption:
1. Generate 12 random bytes (nonce) via `RandomNumberGenerator.Fill`.
2. Encrypt plaintext with AES-GCM using the nonce and AAD.
3. Write envelope: `[nonce][ciphertext][tag]`.
4. Emit 32-byte integrity tag: GCM tag zero-padded to 32 bytes.

### 3.2 Additional Authenticated Data (AAD)

```
AAD = block_index as int64, little-endian (8 bytes)
```

The block index is included as AAD during both encryption and decryption. This
binds each block's ciphertext to its position in the file:

```
Block 0 encrypted with AAD = 0x0000000000000000
Block 1 encrypted with AAD = 0x0100000000000000
Block N encrypted with AAD = N as int64 LE

If an attacker swaps blocks 0 and 1:
  Decrypt block 1 at position 0 with AAD=0 --> tag mismatch (was AAD=1)
  Decrypt block 0 at position 1 with AAD=1 --> tag mismatch (was AAD=0)
```

### 3.3 Integrity Hash (File-Level)

The file-level integrity hash is the XOR of all per-block integrity tags:

```
integrity_hash = tag[0] XOR tag[1] XOR ... XOR tag[N]
```

Each `tag[i]` is the 16-byte GCM authentication tag zero-padded to 32 bytes.

**Properties of XOR integrity:**
- O(1) update: `hash_new = hash_old XOR tag_old XOR tag_new`
- Order-independent (commutative, associative)
- Detects any single-block modification
- Stored in the Protobuf header inside block 0

**IntegrityTracker operations:**
- `UpdateIntegrity(blockIndex, newTag)`: XOR out old tag, XOR in new tag.
- `RecordBlockHash(blockIndex, tag)`: cache tag without modifying running hash
  (used during reads).
- `RemoveBlock(blockIndex)`: XOR out tag contribution (used during truncation).

### 3.4 Pluggable Crypto Architecture

```
                    IBlockCryptoFactory
                    +-------------------+
                    | DefaultAlgorithmId|
                    | Create()          |---- creates ---> IBlockCrypto
                    | CreateForAlgorithm|                  +-----------------+
                    | GetCiphertextOvhd |                  | AlgorithmId     |
                    +-------------------+                  | CiphertextOvhd  |
                           ^                               | IntegrityTagSize|
                           |                               | Encrypt()       |
                    BlockCryptoFactory                      | Decrypt()       |
                    (switch on AlgorithmId)                 +-----------------+
                                                                  ^
                                                                  |
                                                           AesGcmBlockCrypto
                                                           (AlgorithmId=0x01)
```

Adding a new algorithm:
1. Implement `IBlockCrypto` with a new `AlgorithmId` byte.
2. Add a case to `BlockCryptoFactory.CreateForAlgorithm()`.
3. The rest of the stack (BlockLayout, BlockManager, WriteBehindBuffer,
   ReadAheadBuffer) is algorithm-agnostic.

**Thread safety:** `IBlockCrypto` instances are **not** thread-safe. Each
parallel worker creates its own instance through the factory. Pre-allocated
buffers (nonce, tag) are reused per call within a single worker.

---

## 4. Block Layout and Geometry

### 4.1 BlockLayout Calculations

`BlockLayout` computes all geometry from two inputs: block size exponent and
ciphertext overhead.

```
BlockSize             = 1 << blockSizeExponent

Block0MaxCT           = BlockSize - CleartextHeaderSize(32) - LengthPrefix(4)
BlockNMaxCT           = BlockSize - LengthPrefix(4)

PayloadCapacity       = Block0MaxCT - CiphertextOverhead
                      (constrained by Block 0, not Block N)

Block0DataStart       = HeaderLengthPrefix(2) + ProtobufMaxSize(85) = 87
Block0DataCapacity    = PayloadCapacity - 87
BlockNDataCapacity    = PayloadCapacity
```

**Key insight:** `PayloadCapacity` is derived from Block 0's smaller ciphertext
budget so that all blocks share the same decrypted payload size. Block N wastes
32 bytes (the cleartext header size) as unused padding at the end of its
physical block -- this is the cost of uniform payload capacity.

### 4.2 Capacity Table (AES-GCM, overhead = 28 bytes)

| BlockSize   | Exponent | Block0MaxCT | PayloadCapacity | Block0DataCapacity | BlockNDataCapacity |
|-------------|----------|-------------|-----------------|--------------------|--------------------|
| 4 KB (4096) | 12       | 4060        | 4032            | 3945               | 4032               |
| 8 KB (8192) | 13       | 8156        | 8128            | 8041               | 8128               |
| 16 KB       | 14       | 16348       | 16320           | 16233              | 16320              |
| 32 KB       | 15       | 32732       | 32704           | 32617              | 32704              |
| 64 KB       | 16       | 65500       | 65472           | 65385              | 65472              |
| 128 KB      | 17       | 131036      | 131008          | 130921             | 131008             |

*Note: Block0MaxCT = BlockSize - 32 - 4. PayloadCapacity = Block0MaxCT - 28.*

### 4.3 Position Mapping

`PositionMapper` translates logical cleartext byte positions to
`(blockIndex, offsetInPayload)`:

```
If cleartextPosition < Block0DataCapacity:
    blockIndex = 0
    offsetInPayload = Block0DataStart + cleartextPosition

Else:
    adjusted = cleartextPosition - Block0DataCapacity
    blockIndex = 1 + adjusted / BlockNDataCapacity
    offsetInPayload = adjusted % BlockNDataCapacity
```

Physical file offset for a block: `blockIndex * BlockSize`.

Block count for a given cleartext length:

```
If length <= 0:                      0 blocks
If length <= Block0DataCapacity:     1 block
Else: 1 + ceil((length - Block0DataCapacity) / BlockNDataCapacity)
```

---

## 5. IO Architecture

### 5.1 Access Patterns

CipheredFileStream supports two access patterns selected at creation time:

```
                          CipheredFileStream
                                |
              +-----------------+-----------------+
              |                                   |
         Sequential                          RandomAccess
         (default)                           (explicit)
              |                                   |
    +---------+---------+                    BlockManager
    |                   |                  (single-block cache)
WriteBehindBuffer  ReadAheadBuffer
 (bulk write)       (bulk read)
    |                   |
    +----> fallback --->+-----> BlockManager
```

**Sequential mode** (default) uses ring buffers for bulk IO with parallel
encrypt/decrypt. It automatically falls back to BlockManager for operations
that break sequential assumptions.

**RandomAccess mode** uses BlockManager directly with a single-block cache.

### 5.2 WriteBehindBuffer (Sequential Writes)

Accumulates plaintext into block-sized slots, encrypts full slots in parallel,
and writes them to disk in bulk.

```
USER WRITES
    |
    v
+-------+-------+-------+-------+
| Slot 0| Slot 1| Slot 2| Slot 3|   (plaintext accumulation)
+-------+-------+-------+-------+
    |       |       |       |
    v       v       v       v        <-- Phase 1: Parallel Encrypt
+-------+-------+-------+-------+
|  CT 0 |  CT 1 |  CT 2 |  CT 3 |   (ciphertext + tags in _rawBuffer)
+-------+-------+-------+-------+
    |                               <-- Phase 2: Serial Integrity Update
    v
IntegrityTracker.UpdateIntegrity()   (per-slot, sequential)
    |                               <-- Phase 3: Bulk IO Write
    v
_underlyingStream.Write(_rawBuffer)  (single system call)
```

**3-phase flush:**
1. **Parallel encrypt**: workers partition slots, each encrypts independently
   using its own `CryptoWorker` (IBlockCrypto + CtBuffer + AadBuffer + IntegrityTagBuffer).
   Integrity tags are captured per-slot in thread-safe non-overlapping arrays.
2. **Serial integrity update**: iterate slots sequentially, call
   `IntegrityTracker.UpdateIntegrity()` for each.
3. **Bulk IO write**: write the entire `_rawBuffer` to the underlying stream in
   a single `Write` call.

**Buffer sizing:** Default 1 MB. Slot count = `max(2, bufferSize / BlockSize)`.

### 5.3 ReadAheadBuffer (Sequential Reads)

Bulk-reads multiple contiguous blocks in a single IO operation, decrypts them
in parallel, and serves subsequent `Read` calls from decrypted slots.

```
_underlyingStream.Read(_rawBuffer)   <-- Bulk IO Read (single system call)
    |
    v
+-------+-------+-------+-------+
| Raw 0 | Raw 1 | Raw 2 | Raw 3 |   (raw ciphertext blocks)
+-------+-------+-------+-------+
    |       |       |       |
    v       v       v       v        <-- Parallel Decrypt
+-------+-------+-------+-------+
| PT 0  | PT 1  | PT 2  | PT 3  |   (decrypted slots)
+-------+-------+-------+-------+
    |
    v
IntegrityTracker.RecordBlockHash()   (per-slot, sequential)
    |
USER READS <--- serve from slots
```

### 5.4 BlockManager (Random Access / Fallback)

Single-block cache for random access and as fallback from sequential mode:

```
EnsureBlock(blockIndex)
    |
    +-- cache hit? --> return (no IO)
    |
    +-- cache miss
         |
         +-- flush dirty cached block (encrypt + write)
         |
         +-- read new block from disk
         |
         +-- decrypt into _cachedPayload
         |
         +-- record integrity tag
```

### 5.5 CryptoWorker Structure

Each parallel worker owns isolated, pre-allocated buffers:

```csharp
struct CryptoWorker : IDisposable
{
    IBlockCrypto Crypto;           // per-worker IBlockCrypto instance
    byte[]       CtBuffer;         // ciphertext working buffer
    byte[]       PtBuffer;         // plaintext working buffer (ReadAheadBuffer only)
    byte[]       AadBuffer;        // 8-byte AAD (block index)
    byte[]       IntegrityTagBuffer; // 32-byte integrity tag
}
```

Workers are **not** shared between threads. The main thread uses `_workers[0]`;
ThreadPool threads use `_workers[1..N-1]`.

### 5.6 Fallback Mechanics

Sequential mode falls back to BlockManager under these conditions:

| Trigger                         | Permanent? | Reason                                    |
|---------------------------------|------------|-------------------------------------------|
| Overwrite write (position < EOF)| Yes        | Cannot maintain sequential append model    |
| `SetLength()`                   | Yes        | Structural file change                     |
| `Seek`/Position setter          | No         | Flushes pending data, does not disable     |
| Mid-block append after `Flush`  | Yes        | Block already has data that would be lost  |

**IsMidBlockAppend** detection: after `Flush`, if position is at EOF but in the
middle of an existing block (i.e., `offsetInPayload != dataStart` and
`blockIndex < blockCount`), WriteBehindBuffer would zero-initialize the slot and
lose existing block data. This triggers permanent fallback.

---

## 6. Key Management

### 6.1 Key Provider Hierarchy

```
IKeyProvider : IDisposable
    |-- GetKey() : byte[32]
    |
    +-- EphemeralKeyProvider       Random 32-byte key, zeroed on dispose
    |
    +-- PasswordKeyProvider        PBKDF2-SHA256 derived key
```

### 6.2 Direct Key

```csharp
var factory = new CipheredFileStreamFactory(keyBytes); // 32-byte key
```

A defensive copy is made internally. The caller may clear the original. The
factory zeroes its copy on `Dispose()`.

### 6.3 PBKDF2-SHA256 (Password-Based)

```csharp
// New file: generates random 16-byte salt
var provider = new PasswordKeyProvider("passphrase", iterations: 600_000);

// Existing file: use salt and iterations from file header
var header = CipheredFileStreamFactory.ReadFileHeader("file.enc");
var provider = new PasswordKeyProvider("passphrase", header.Salt, header.KdfIterations);
```

| Parameter  | Value                               |
|------------|-------------------------------------|
| Algorithm  | PBKDF2 with HMAC-SHA256             |
| Salt       | 16 bytes, cryptographically random  |
| Iterations | Default 600,000 (configurable)      |
| Output     | 32 bytes (AES-256 key)              |

KDF parameters (method, salt, iterations) are stored in the cleartext header
so they can be read before any key material is available.

### 6.4 Ephemeral Keys

```csharp
using var provider = new EphemeralKeyProvider(); // random 32-byte key
```

Generates a random key on construction. Useful for temporary/session-scoped
encrypted files. Key is zeroed on dispose.

### 6.5 Header Inspection

```csharp
FileHeaderInfo header = CipheredFileStreamFactory.ReadFileHeader("file.enc");
// header.KdfMethod, header.Salt, header.KdfIterations, header.AlgorithmId, ...
```

`ReadFileHeader` is a static utility that reads only the 32-byte cleartext
header. It validates magic bytes and version but requires no key. This enables
a two-phase open workflow: inspect header first, then provide the correct key
or password.

---

## 7. Public API

### 7.1 Factory Pattern

```csharp
public interface ICipheredStreamFactory : IDisposable
{
    Stream Create(string path, FileMode mode,
                  CipheredFileStreamOptions? options = null);
    Stream Create(string path, FileMode mode, FileAccess access,
                  CipheredFileStreamOptions? options = null);
    Stream Create(string path, FileMode mode, FileAccess access,
                  FileShare share, CipheredFileStreamOptions? options = null);
}
```

The concrete implementation is `CipheredFileStreamFactory`:

```csharp
// Direct key
var factory = new CipheredFileStreamFactory(keyBytes);

// Key provider (password or ephemeral)
var factory = new CipheredFileStreamFactory(keyProvider);

// Static header inspection
FileHeaderInfo info = CipheredFileStreamFactory.ReadFileHeader(path);
```

The factory returns a standard `Stream`. The internal `CipheredFileStream`
class is not publicly exposed.

### 7.2 CipheredFileStreamOptions

```csharp
public class CipheredFileStreamOptions
{
    BlockSizeOption      BlockSize        { get; set; } = Block16K;
    AccessPattern        AccessPattern    { get; set; } = Sequential;
    int                  BufferSize       { get; set; } = 0;      // 0 = default (1 MB)
    int                  ConcurrencyLevel { get; set; } = 0;      // 0 = default (2)
    EncryptionAlgorithm  Algorithm        { get; set; } = AesGcm;
}
```

| Option           | Values                                 | Notes                                     |
|------------------|----------------------------------------|-------------------------------------------|
| `BlockSize`      | `Block4K` .. `Block128K` (enum)        | For new files only; existing files use header |
| `AccessPattern`  | `Sequential`, `RandomAccess`           | Selects IO strategy                       |
| `BufferSize`     | 0 or positive int                      | Ring buffer size (sequential mode)        |
| `ConcurrencyLevel`| 0..N                                  | 0=default(2), 1=serial, capped at CPU count |
| `Algorithm`      | `AesGcm` (0x01)                        | For new files only; existing files auto-detect |

### 7.3 Enumerations

```csharp
public enum BlockSizeOption      // Exponents 12..17
{
    Block4K = 12, Block8K = 13, Block16K = 14,
    Block32K = 15, Block64K = 16, Block128K = 17
}

public enum AccessPattern        { Sequential, RandomAccess }
public enum EncryptionAlgorithm : byte { AesGcm = 0x01 }
public enum KdfMethod : byte     { None = 0x00, Pbkdf2Sha256 = 0x01 }
```

### 7.4 Key Providers

```csharp
public interface IKeyProvider : IDisposable
{
    byte[] GetKey();  // returns 32-byte key
}

public sealed class EphemeralKeyProvider : IKeyProvider { ... }
public sealed class PasswordKeyProvider  : IKeyProvider
{
    const int DefaultIterations = 600_000;
    byte[] Salt { get; }
    uint Iterations { get; }
}
```

### 7.5 FileHeaderInfo

```csharp
public readonly struct FileHeaderInfo
{
    ushort    FormatVersion     { get; init; }
    int       BlockSizeExponent { get; init; }
    byte      AlgorithmId       { get; init; }
    KdfMethod KdfMethod         { get; init; }
    byte[]?   Salt              { get; init; }  // null when KdfMethod=None
    uint      KdfIterations     { get; init; }  // 0 when KdfMethod=None
}
```

### 7.6 Stream Behavior

The returned `Stream` supports:

| Operation          | Behavior                                              |
|--------------------|-------------------------------------------------------|
| `Read`/`ReadAsync` | Decrypt and return plaintext                          |
| `Write`/`WriteAsync`| Encrypt and write ciphertext                         |
| `Seek`             | Flush pending data, reposition                        |
| `Position` setter  | Flush pending data, reposition                        |
| `SetLength`        | Truncate or extend with zeros; permanent fallback     |
| `Flush`            | Write all pending data and update header               |
| `Dispose`          | Flush, dispose underlying stream, zero key material   |
| `Length`            | Returns logical cleartext file size                   |

File modes `Create`, `CreateNew`, `Truncate`, and `OpenOrCreate` (empty file)
initialize a new encrypted file. `Open` and `OpenOrCreate` (existing file) read
the header and auto-detect block size and algorithm. `Append` is converted to
`OpenOrCreate` + `ReadWrite` with position set to EOF.

Write-only access (`FileAccess.Write`) is automatically promoted to
`FileAccess.ReadWrite` because the stream must read/write block headers.

---

## 8. Security Properties

### 8.1 Guarantees

| Property                        | Mechanism                                      |
|---------------------------------|------------------------------------------------|
| Confidentiality                 | AES-256-GCM with per-block random 12-byte nonce|
| Per-block authentication        | GCM auth tag (128-bit) verified on every read  |
| Block reordering detection      | AAD = block index (int64 LE)                   |
| File-level integrity            | XOR of per-block GCM tags (32 bytes)           |
| Wrong key detection             | GCM auth fails immediately                     |
| Key zeroing on dispose          | `Array.Clear` on all key material              |
| Verify-before-decrypt           | Built into GCM (tag check precedes decryption) |

### 8.2 Non-Guarantees

| Non-property                    | Reason                                          |
|---------------------------------|-------------------------------------------------|
| Block truncation detection      | Attacker can remove trailing blocks; block_count in header helps but header can be tampered |
| File size hiding                | Number of blocks reveals approximate plaintext size |
| Thread safety                   | Not thread-safe; matches `FileStream` contract  |
| Atomic writes                   | Crash during write can leave partial state       |

### 8.3 Nonce Management

Each block uses a fresh 12-byte random nonce generated by
`RandomNumberGenerator.Fill()`. Nonces are not derived from block indices or
counters. With 2^96 possible nonces and random selection, the birthday bound
for collision is approximately 2^48 encryptions -- far beyond practical use for
file-level encryption.

### 8.4 Disposal and Key Hygiene

On `Dispose()` / `DisposeAsync()`:
1. Flush all pending writes.
2. Dispose `ReadAheadBuffer` and `WriteBehindBuffer` (zeroes all internal buffers).
3. Dispose `BlockManager` (zeroes cached payload, ciphertext, plaintext buffers).
4. Dispose underlying `FileStream`.
5. `Array.Clear(_key)` -- zero the local key copy.

`CipheredFileStreamFactory.Dispose()` zeroes its key copy.
`PasswordKeyProvider.Dispose()` zeroes the derived key.
`EphemeralKeyProvider.Dispose()` zeroes the random key.

---

## 9. Performance

### 9.1 Measured Throughput

Sequential read/write throughput measured with AES-GCM, parallel workers,
1 MB buffer (default settings):

| Block Size | Write (MB/s) | Read (MB/s) |
|------------|--------------|-------------|
| 4 KB       | 382          | 1,843       |
| 8 KB       | 770          | 2,701       |
| 16 KB      | 1,139        | 3,067       |
| 32 KB      | 1,672        | 2,600       |
| 64 KB      | 2,072        | 3,147       |
| 128 KB     | 2,361        | 3,135       |

### 9.2 Performance Architecture

```
                     Sequential Write Pipeline
                     =========================

User Write() calls
        |
        v
  +-------------------+
  | WriteBehindBuffer  |  Accumulate plaintext into slots
  | (ring buffer)      |
  +-------------------+
        |  buffer full
        v
  +-------------------+
  | Phase 1: Encrypt  |  Parallel (ThreadPool workers)
  | N slots / M cores |  Each worker: own IBlockCrypto + buffers
  +-------------------+
        |  all slots encrypted
        v
  +-------------------+
  | Phase 2: Integrity|  Serial (IntegrityTracker.UpdateIntegrity)
  | N tag updates     |  O(1) per block (XOR)
  +-------------------+
        |
        v
  +-------------------+
  | Phase 3: Bulk IO  |  Single Stream.Write() for N blocks
  +-------------------+

                     Sequential Read Pipeline
                     ========================

  +-------------------+
  | Phase 1: Bulk IO  |  Single Stream.Read() for N blocks
  +-------------------+
        |
        v
  +-------------------+
  | Phase 2: Decrypt  |  Parallel (ThreadPool workers)
  | N slots / M cores |
  +-------------------+
        |
        v
  +-------------------+
  | Phase 3: Record   |  Serial (IntegrityTracker.RecordBlockHash)
  +-------------------+
        |
        v
User Read() calls served from decrypted slots
```

### 9.3 Parallelism Model

- Workers are partitioned across slots: `partition_size = slots / concurrency`.
- Main thread processes partition 0; ThreadPool threads process partitions 1..N-1.
- `Volatile.Read`/`Volatile.Write` on an abort flag enables early termination.
- `Monitor.Wait`/`Pulse` synchronizes worker completion.
- Parallelism is skipped when `slots < concurrency * 2` (overhead not worthwhile).
- Concurrency is capped at `Environment.ProcessorCount`.
- Default concurrency: 2 workers.

### 9.4 Why 16K is the Recommended Default

- **Crypto efficiency**: larger blocks amortize the 28-byte/block AES-GCM
  overhead (0.17% at 16K vs 0.68% at 4K).
- **Memory footprint**: 1 MB buffer holds ~62 slots at 16K.
- **Random access**: 16K is reasonable read amplification for random single-byte
  reads.
- **Throughput**: 1,139 MB/s write, 3,067 MB/s read -- good balance without the
  diminishing returns of very large blocks.

---

## 10. Error Handling

### 10.1 Exception Types

| Exception                         | Condition                                           |
|-----------------------------------|-----------------------------------------------------|
| `EncryptedFileCorruptException`   | Magic bytes invalid, ciphertext length invalid, GCM auth failure, integrity mismatch |
| `EncryptedFileVersionException`   | File format version newer than supported            |
| `ArgumentException`               | Invalid key length, empty password, bad salt size   |
| `ArgumentOutOfRangeException`     | Invalid block size exponent, negative position      |
| `ObjectDisposedException`         | Access after Dispose                                |
| `NotSupportedException`           | Read on write-only, write on read-only              |
| `EndOfStreamException`            | Truncated block on disk                             |
| `IOException`                     | Underlying IO errors, negative seek                 |
| `InvalidOperationException`       | Encryption failure, protobuf header too large       |

### 10.2 EncryptedFileCorruptException

```csharp
public class EncryptedFileCorruptException : Exception
{
    int?    BlockIndex { get; }   // block where corruption detected
    string? FilePath   { get; }   // file path, if known

    static BlockAuthenticationFailed(int blockIndex, string? filePath);
    static InvalidMagicBytes(string? filePath);
    static IntegrityHashMismatch(string? filePath);
}
```

### 10.3 EncryptedFileVersionException

```csharp
public class EncryptedFileVersionException : Exception
{
    ushort  FileVersion        { get; }  // version in file
    ushort  MaxSupportedVersion { get; } // max this library supports
    string? FilePath           { get; }
}
```

---

## 11. Extensibility

### 11.1 Adding a New Encryption Algorithm

1. Choose an unused algorithm ID byte (e.g., `0x02`).
2. Implement `IBlockCrypto`:
   - `AlgorithmId` -- return the new byte.
   - `CiphertextOverhead` -- nonce + tag + any padding overhead.
   - `IntegrityTagSize` -- always 32 bytes (zero-pad if native tag is smaller).
   - `Encrypt()` / `Decrypt()` -- envelope format is implementation-defined.
   - Pre-allocate all buffers in the constructor. Instance is **not** thread-safe.
3. Add a case to `BlockCryptoFactory`:
   - `CreateForAlgorithm()` -- instantiate the new class.
   - `GetCiphertextOverhead()` -- return the overhead constant.
4. Optionally add a new `EncryptionAlgorithm` enum value for the public API.

No changes are needed to `BlockLayout`, `BlockManager`, `WriteBehindBuffer`,
`ReadAheadBuffer`, `IntegrityTracker`, `PositionMapper`, or `CipheredFileStream`.
The file format accommodates new algorithms via the `AlgorithmId` byte in the
cleartext header.

### 11.2 Adding a New KDF Method

1. Choose an unused `KdfMethod` byte (e.g., `0x02` for Argon2).
2. Implement a new `IKeyProvider` that derives a 32-byte key.
3. Update `CipheredFileStreamFactory` to detect the new provider type and write
   the appropriate `KdfMethod` byte and parameters to the cleartext header.
4. Allocate any new header fields from the 4 reserved bytes (offsets 28-31).

### 11.3 Format Version Compatibility

The cleartext header contains `FormatVersion` and `MaxSupportedVersion`:
- Files with `version < FormatVersion` are rejected (too old).
- Files with `version > MaxSupportedVersion` are rejected (too new).
- Currently both are `0x0003`.

Future format changes increment `FormatVersion`. Older libraries reject newer
files with `EncryptedFileVersionException`, which includes both the file version
and the max supported version for diagnostic clarity.
