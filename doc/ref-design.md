# CipheredFileStream Design Document

## 1. Overview

`CipheredFileStream` is a transparent block-level encryption layer that extends `System.IO.Stream`
to serve as a drop-in replacement for `FileStream`. Callers use the standard `Read`, `Write`,
`Seek`, and `SetLength` APIs; the stream transparently encrypts data on write and decrypts on
read, block by block, against an underlying `FileStream`.

**Key design goals:**

- **Drop-in replacement** -- any code that works with `Stream` works with `CipheredFileStream`
  without modification.
- **Block-level authenticated encryption** -- each block is independently encrypted and
  authenticated. Corruption or tampering of any single block is detected immediately.
- **Minimal per-call allocation** in the hot crypto path (via `OptimizedBlockCrypto`).
  All application-level buffers are pre-allocated; the only remaining per-call allocation
  is from the BCL `Aes.Key` setter (internal key-schedule expansion).
- **Configurable block sizes** (4K to 128K) to tune the tradeoff between metadata overhead
  and crypto throughput.
- **Two access patterns** -- Sequential (ring buffers for bulk IO) and RandomAccess (single-block
  cache), with automatic fallback from Sequential to RandomAccess when non-sequential access is
  detected.

The public entry point is `CipheredFileStreamFactory`, which implements `ICipheredStreamFactory`.
Callers never instantiate `CipheredFileStream` directly -- it is `internal`.

---

## 2. File Format (v2)

Format version: `0x0002`. Magic bytes: `0x42 0x43` (ASCII `"BC"`).

### 2.1 Physical Layout

```
+--------+--------+--------+--------+--------+--------+---
|Block 0 |Block 1 |Block 2 |Block 3 |  ...   |Block N |
|        |        |        |        |        |        |
+--------+--------+--------+--------+--------+--------+---
<-BS----> <-BS----> <-BS----> <-BS---->         <-BS---->

BS = Block Size (configurable: 4K, 8K, 16K, 32K, 64K, 128K)
All blocks are the same physical size.
```

### 2.2 Block 0 — Complete Structure (all layers)

Block 0 is the most complex block. It contains four nested layers:

**Layer 1: Physical on-disk layout**

```
BLOCK 0 — ON DISK (BlockSize bytes)
┌──────────────────┬────────────┬──────────────────────────────┬──────────┐
│ Cleartext Header │  CT Length │        Ciphertext            │ Padding  │
│     8 bytes      │  4 bytes   │  (encrypted envelope)        │ (zeros)  │
│   UNENCRYPTED    │  uint32 LE │                              │          │
└──────────────────┴────────────┴──────────────────────────────┴──────────┘
│← byte [0..7] ──→│←[8..11]──→│←── [12..N] ────────────────→│←to BS──→│
```

**Layer 2: Cleartext header (bytes 0-7, readable without key)**

```
Offset  Size  Field                    Value
------  ----  -----------------------  ---------------------------
0       2B    Magic bytes              0x42 0x43 (ASCII "BC")
2       2B    Format version           0x0002 (little-endian)
4       1B    Block size exponent      12-17 (4K=12, 8K=13, ..., 128K=17)
5       3B    Reserved                 0x000000
```

**Layer 3: Ciphertext envelope (bytes 12..N, encrypted)**

The ciphertext region contains an AES-256-CBC-HMAC-SHA512 authenticated envelope
(RFC 7518 Section 5.2.5 style), output of `OptimizedBlockCrypto.Encrypt`:

```
CIPHERTEXT ENVELOPE
┌──────┬──────────────┬──────────┬────────────────────────────────────────┐
│ Algo │   MAC Tag    │    IV    │    AES-256-CBC Ciphertext (PKCS7)      │
│  1B  │    32B       │   16B    │     ((payload/16)+1)*16 bytes          │
│ 0x01 │ HMAC-SHA512  │ random   │                                        │
│      │ (truncated)  │          │                                        │
└──────┴──────────────┴──────────┴────────────────────────────────────────┘
│←──── 49 bytes base overhead ───→│←── variable (PKCS7 always pads) ────→│

  Algo byte:   0x01 = AES-256-CBC-HMAC-SHA512
  MAC Tag:     First 32 bytes of HMAC-SHA512 output (truncated from 64)
  IV:          16 cryptographically random bytes (fresh per block write)
  AES ciphertext: AES-256-CBC(aes_key, IV, plaintext, PKCS7 padding)
```

**Layer 4: Decrypted payload (after HMAC verify + AES decrypt)**

After decrypting the envelope, the payload contains a Protobuf metadata header
followed by user data:

```
DECRYPTED PAYLOAD (PayloadCapacity bytes, e.g. 16304 at 16K)
┌────────────┬─────────────────────────────┬─────────────────────────────┐
│ Hdr Len 2B │   Protobuf Header (<=85B)   │         User Data           │
│  uint16 LE │                             │     (Block0DataCapacity)     │
├────────────┼─────────────────────────────┼─────────────────────────────┤
│ offset 0   │ offset 2                    │ offset 87                   │
│            │                             │ = HeaderLenPrefix(2)        │
│            │                             │   + ProtobufHeaderMax(85)   │
└────────────┴─────────────────────────────┴─────────────────────────────┘
```

The 85-byte Protobuf region is always reserved even if the actual serialized header is
smaller (proto3 omits zero-value fields). This keeps the user data offset fixed at 87.

**Protobuf header fields** (`EncryptedFileHeader`):

```
Field                    Type       Wire size  Description
-----------------------  ---------  ---------  ---------------------------------
cleartext_length         sfixed64    9 bytes   Logical file size in bytes
integrity_hash           bytes      66 bytes   64B SHA-512 XOR of all block
                                               ciphertext hashes
block_count              sfixed32    5 bytes   Number of physical blocks
header_version           sfixed32    5 bytes   Schema version (1)
                                   ---------
                                   85B max
```

`cleartext_length` is the key field — it tells the reader how many bytes of user data
are actually meaningful across all blocks (see Section 2.4 on partial last blocks).

### 2.3 Block N (middle blocks, 1 <= N < last) — Complete Structure

Middle blocks are simpler — no cleartext header, no Protobuf overhead.

**Layer 1: Physical on-disk layout**

```
BLOCK N — ON DISK (BlockSize bytes)
┌────────────┬──────────────────────────────────────┬────────────────────┐
│  CT Length  │              Ciphertext              │      Padding       │
│  4 bytes    │        (encrypted envelope)          │      (zeros)       │
│  uint32 LE  │                                      │                    │
└────────────┴──────────────────────────────────────┴────────────────────┘
│← [0..3] ─→│←──── [4..N] ───────────────────────→│←── to BlockSize ─→│
```

**Layer 2: Ciphertext envelope** — same format as Block 0 (see Section 2.2 Layer 3).

**Layer 3: Decrypted payload** — entire payload is user data, no header overhead:

```
DECRYPTED PAYLOAD (PayloadCapacity bytes)
┌────────────────────────────────────────────────────────────────────────┐
│                    User Data (PayloadCapacity bytes)                    │
│                    All bytes are meaningful user content.               │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.4 Last Block — Partial Data

The last block is physically identical to any other block (same BlockSize, same
ciphertext envelope, same PayloadCapacity after decryption). However, it may only
be partially filled with real user data:

**When the last block is Block N (N >= 1):**

```
LAST BLOCK N — DECRYPTED PAYLOAD (PayloadCapacity bytes)
┌──────────────────────────────────┬─────────────────────────────────────┐
│          Real User Data          │          Zero Padding               │
│          (K bytes)               │    (PayloadCapacity - K bytes)      │
└──────────────────────────────────┴─────────────────────────────────────┘
│←── meaningful data ────────────→│←── zeros, encrypted but ignored ──→│

K = cleartextLength - Block0DataCapacity - (lastBlockIndex - 1) * BlockNDataCapacity
```

**When the last block is Block 0 (single-block file):**

```
LAST BLOCK 0 — DECRYPTED PAYLOAD (PayloadCapacity bytes)
┌────────────┬──────────────────┬───────────────────┬─────────────────┐
│ Hdr Len 2B │ Protobuf (<=85B) │  Real User Data   │  Zero Padding   │
│            │                  │    (K bytes)       │(B0DataCap - K)  │
└────────────┴──────────────────┴───────────────────┴─────────────────┘
│←──── header area (87B) ──────→│←── meaningful ──→│←── zeros ──────→│

K = cleartextLength
Padding = Block0DataCapacity - K  (not PayloadCapacity - K)
```

The entire PayloadCapacity is always encrypted — the ciphertext size is constant
regardless of how much real data the block holds. An observer cannot tell whether
the last block contains 1 byte or is completely full. The reader must decrypt
Block 0's Protobuf header and read `cleartext_length` to know where real data ends.

---

## 3. Crypto Scheme

**Algorithm:** AES-256-CBC + HMAC-SHA512 with SP800-108 CTR KDF (identical to the R9
`Microsoft.R9.Extensions.Cryptography.Encryption` scheme).

### 3.1 Per-Block Encryption Flow

```
                           32-byte master key
                                  |
                                  v
                     +------------------------+
                     | SP800-108 CTR KDF      |
    Random IV -----> | HMAC-SHA512(key, input) |
    (16 bytes)       | input = [counter=1]     |
                     |   [label: "MSFT_KDF..."]|
                     |   [0x00][IV][keyLen=512] |
                     +------------------------+
                                  |
                         64-byte derived key
                        /                    \
                32B HMAC key            32B AES key
                    |                        |
                    v                        v
             +------------+         +------------------+
             | HMAC-SHA512|         | AES-256-CBC      |
             | Verify tag |         | Encrypt/Decrypt  |
             | (32B tag)  |         | (PKCS7 padding)  |
             +------------+         +------------------+
                    |                        |
                    v                        v
            Authentication           Confidentiality

  Ciphertext output: [0x01][32B HMAC tag][16B IV][AES-CBC ciphertext]
```

### 3.2 Encryption Steps

1. Generate 16 random bytes for the IV.
2. Derive a 64-byte AEAD key via SP800-108 CTR KDF (HMAC-SHA512 with the master key).
   - The IV is used as the KDF context, binding the derived key to this specific block write.
3. Split the derived key: first 32 bytes = HMAC key, last 32 bytes = AES key.
4. Encrypt the plaintext payload with AES-256-CBC using PKCS7 padding.
5. Compute HMAC-SHA512 over: `[0x01][AAD][IV][ciphertext][adLen_in_bits]`.
6. Truncate the HMAC to 32 bytes as the authentication tag.
7. Output: `[0x01][32B tag][16B IV][AES-CBC ciphertext]`.

### 3.3 Decryption Steps (Verify Before Decrypt)

1. Extract the IV from the ciphertext envelope.
2. Derive the AEAD key via SP800-108 CTR KDF (same as encryption).
3. **Verify the HMAC authentication tag first** (constant-time comparison).
   - If verification fails, return -1 immediately. The plaintext is never produced.
4. Only after successful authentication, decrypt with AES-256-CBC.

**Why verify-before-decrypt:** This prevents chosen-ciphertext attacks. An attacker who can
submit modified ciphertexts and observe the decryption behavior (padding oracle, timing, etc.)
gets no information because altered blocks are rejected before decryption begins.

### 3.4 AAD Binding (Block Reordering Prevention)

The Additional Authenticated Data (AAD) for each block is its **8-byte little-endian block
index**. This is included in the HMAC computation:

```
AAD = BitConverter.GetBytes((long)blockIndex)    // 8 bytes, LE
```

This binds each block's authentication tag to its position in the file. If an attacker swaps
blocks 3 and 7 on disk, the HMAC verification fails for both because the AAD no longer matches.

---

## 4. Architecture

### 4.1 Class Diagram

```
                    +-----------------------------+
                    | ICipheredStreamFactory      |
                    | (public interface)          |
                    |   Create(path, mode, ...) --+---> Stream
                    +-----------------------------+
                                |
                                | implements
                                v
                    +-----------------------------+
                    | CipheredFileStreamFactory   |  <--- IKeyProvider / byte[] key
                    | (public sealed class)       |
                    |   _key: byte[32]            |
                    |   Create() { ... }          |
                    +-----------------------------+
                                |
                                | creates (internal)
                                v
            +---------------------------------------+
            | CipheredFileStream : Stream            |
            | (internal sealed class)               |
            |                                        |
            |   _blockManager: BlockManager          |----> Handles random access
            |   _readBuffer:  ReadAheadBuffer?       |----> Handles sequential read
            |   _writeBuffer: WriteBehindBuffer?     |----> Handles sequential write
            |   _positionMapper: PositionMapper      |
            |   _integrityTracker: IntegrityTracker  |
            |   _layout: BlockLayout                 |
            +---------------------------------------+
               |             |              |
               v             v              v
    +---------------+  +----------------+  +------------------+
    | BlockManager  |  | ReadAheadBuffer|  | WriteBehindBuffer|
    | (single-block |  | (bulk-read N   |  | (bulk-write N    |
    |  cache, R/W)  |  |  blocks, read) |  |  blocks, write)  |
    +---------------+  +----------------+  +------------------+
           |                  |                    |
           v                  v                    v
    +------------------------------------------------------+
    | OptimizedBlockCrypto                                 |
    | (AES-256-CBC + HMAC-SHA512, minimal per-call alloc)  |
    +------------------------------------------------------+

    Supporting classes:
    +---------------+  +----------------+  +-------------------+
    | BlockLayout   |  | PositionMapper |  | IntegrityTracker  |
    | (geometry)    |  | (cleartext pos |  | (XOR of SHA512    |
    |               |  |  -> block/off) |  |  block hashes)    |
    +---------------+  +----------------+  +-------------------+

    +-------------------+
    | EncryptedFileFormat|
    | (constants)       |
    +-------------------+
```

### 4.2 Component Responsibilities

| Component                  | Responsibility                                                  |
|----------------------------|-----------------------------------------------------------------|
| `CipheredFileStreamFactory`| Public API. Creates `FileStream` + `CipheredFileStream`. Manages key lifecycle. |
| `CipheredFileStream`       | Stream facade. Routes reads/writes to BlockManager or ring buffers. Manages header, position, length. |
| `BlockManager`             | Single-block cache. Loads/decrypts one block at a time, writes back when dirty. Used by RandomAccess mode and as fallback. |
| `ReadAheadBuffer`          | Bulk-reads N contiguous blocks in one IO syscall, decrypts all, serves from decrypted slots. Sequential read path. |
| `WriteBehindBuffer`        | Accumulates plaintext into N block-sized slots, encrypts full slots, bulk-writes in one IO syscall. Sequential write path. |
| `OptimizedBlockCrypto`     | Minimal-allocation encrypt/decrypt. Same crypto scheme as R9 but pre-allocates all application-level buffers. |
| `BlockLayout`              | Computes block geometry from a block size exponent: payload capacity, data capacity, max ciphertext sizes. |
| `PositionMapper`           | Maps cleartext byte positions to (blockIndex, offsetInPayload). Accounts for block 0 header area. |
| `IntegrityTracker`         | Maintains an XOR of SHA512 hashes of all block ciphertexts. O(1) update on block modification. |
| `EncryptedFileFormat`      | Static constants: magic bytes, version, header sizes, overhead values, exponent bounds. |

---

## 5. Access Patterns

### 5.1 Sequential Mode (Default)

When `AccessPattern.Sequential` is selected (the default), CipheredFileStream uses ring buffers
for bulk IO:

```
Sequential Read (ReadAheadBuffer):
  1. Caller calls Read(buf, 0, 64KB)
  2. CipheredFileStream delegates to ReadAheadBuffer
  3. ReadAheadBuffer checks if the target block is in its slot array
  4. If not: bulk-read N blocks from disk in ONE read syscall
     (N = bufferSize / blockSize, default ~64 blocks for 1MB / 16K)
  5. Decrypt all N blocks into pre-allocated payload slots
  6. Copy requested data from the appropriate slot(s) to caller's buffer
  7. Subsequent reads hit the already-decrypted slots (no disk IO, no crypto)
  8. When reads advance past the buffered range, refill with the next N blocks

Sequential Write (WriteBehindBuffer):
  1. Caller calls Write(buf, 0, 64KB)
  2. CipheredFileStream delegates to WriteBehindBuffer
  3. Data is copied into block-sized plaintext slots
  4. When a slot is full, it stays in buffer
  5. When all N slots are full: encrypt all N blocks, bulk-write ONE syscall
  6. On Flush/Dispose: encrypt and write any remaining partial slots
```

**Benefits of bulk IO:**
- Amortizes kernel-to-user transition overhead across N blocks.
- Enables OS-level readahead via `FileOptions.SequentialScan`.
- Reduces the number of `FileStream.Position` seeks.

### 5.2 RandomAccess Mode

When `AccessPattern.RandomAccess` is selected, CipheredFileStream uses `BlockManager` directly:

```
RandomAccess Read/Write:
  1. Map cleartext position to (blockIndex, offset)
  2. If blockIndex != cached block: flush dirty, load new block (one disk read)
  3. Read from or write to the cached payload
  4. On next block access: flush if dirty, load new (one disk write + one disk read)
```

This mode has minimal memory overhead (one block cache) but does one IO per block transition.

### 5.3 Auto-Fallback from Sequential to RandomAccess

Sequential mode automatically falls back to BlockManager when non-sequential access is detected:

- **Write to position before EOF** (overwrite) triggers fallback.
- **Write to position beyond EOF** (gap) triggers fallback.
- **SetLength** triggers fallback.

The fallback is one-way and permanent for the stream's lifetime:

```
FallBackToBlockManager():
  1. Flush any pending WriteBehindBuffer data to disk
  2. Invalidate BlockManager cache (ring buffer may have written blocks)
  3. Set _sequentialFallback = true
  4. All subsequent reads/writes go through BlockManager
```

---

## 6. Configurable Block Sizes

### 6.1 Supported Sizes

| Enum Value      | Exponent | Block Size | Payload Capacity | Block 0 Data Capacity |
|-----------------|----------|------------|------------------|-----------------------|
| `Block4K`       | 12       | 4,096 B    | 4,016 B          | 3,929 B               |
| `Block8K`       | 13       | 8,192 B    | 8,112 B          | 8,025 B               |
| `Block16K`      | 14       | 16,384 B   | 16,304 B         | 16,217 B              |
| `Block32K`      | 15       | 32,768 B   | 32,688 B         | 32,601 B              |
| `Block64K`      | 16       | 65,536 B   | 65,456 B         | 65,369 B              |
| `Block128K`     | 17       | 131,072 B  | 130,992 B        | 130,905 B             |

### 6.2 Payload Capacity Formula

```
PayloadCapacity = ((BlockNMaxCiphertextSize - R9BaseOverhead) / 16 - 1) * 16

Where:
  BlockNMaxCiphertextSize = BlockSize - 4     (4-byte length prefix)
  R9BaseOverhead          = 49                (1B algo + 32B MAC + 16B IV)
  The /16 and *16 account for AES-CBC 16-byte alignment
  The -1 accounts for mandatory PKCS7 padding block (always adds 1..16 bytes)
```

Block 0 and Block N yield the **same** payload capacity because the 8-byte cleartext header
difference falls within the same AES 16-byte alignment bucket. This simplifies the design --
every block has the same decrypted payload size.

### 6.3 Why 16K is the Default

16K (`Block16K`, exponent 14) is the default because it provides the best balance:

- **Crypto efficiency:** Larger blocks amortize the fixed 49-byte R9 overhead and per-block HMAC
  cost across more payload bytes. At 16K, overhead is ~0.3% (compared to ~1.2% at 4K).
- **Memory footprint:** A 1MB ring buffer holds ~64 blocks at 16K, providing good read-ahead
  depth. At 128K, the same 1MB holds only ~8 blocks.
- **Random access granularity:** On random access patterns, each miss loads one full block. 16K
  is a reasonable read amplification penalty. At 128K, a single byte read loads 128K.
- **Throughput:** 16K blocks achieve ~92% of the theoretical crypto throughput ceiling for
  sequential reads (see Section 8).

### 6.4 Block Size Stored in File

The block size exponent is stored at byte offset 4 in the cleartext header. When opening an
existing file, the block size is read from the header and the `BlockLayout` is reconstructed.
The `BlockSize` option in `CipheredFileStreamOptions` is ignored for existing files.

---

## 7. OptimizedBlockCrypto

### 7.1 Design Goal: Minimal Per-Call Allocation

The R9 SDK `Encryption.Encrypt`/`Decrypt` methods allocate ~10 temporary objects on every call.
`OptimizedBlockCrypto` pre-allocates all application-level buffers, eliminating most GC pressure:

| R9 Allocation (per call)               | Size     | OptimizedBlockCrypto                    |
|-----------------------------------------|----------|-----------------------------------------|
| KDF input byte array                    | 58 B     | Pre-allocated `_kdfInput` (once)        |
| KDF output byte array                   | 64 B     | Pre-allocated `_kdfOutput` (once)       |
| AEAD key byte array                     | 64 B     | Pre-allocated `_aeadKey` (once)         |
| AES key `.ToArray()` copy               | 32 B     | Pre-allocated `_aesKeyBuf` (once)       |
| HMAC key `.ToArray()` copy              | 32 B     | Pre-allocated `_hmacKeyBuf` (once)      |
| `new HMACSHA512(key)` instance          | ~200 B   | `HMACSHA512.TryHashData()` (one-shot)   |
| HMAC input concatenation                | ~16K+    | Pre-allocated `_hmacInput` (once)       |

**Key optimization:** `HMACSHA512.TryHashData()` is a static one-shot API that avoids creating
an `HMACSHA512` instance (which internally allocates a hash state and calls `Initialize`).

**Remaining BCL allocation:** The `_aes.Key = _aesKeyBuf` setter triggers an internal
key-schedule expansion inside the .NET BCL `Aes` class. This is a BCL implementation detail
that cannot be eliminated with the current `TryEncryptCbc`/`TryDecryptCbc` API shape. Since
the KDF derives a new key per block, caching the `ICryptoTransform` is not possible.

### 7.2 Pre-Allocated Buffers

```csharp
// All allocated once in the constructor:
_kdfInput       = new byte[58];       // KDF input (overwrite IV per call)
_aeadKey        = new byte[64];       // Derived key (32 MAC + 32 ENC)
_iv             = new byte[16];       // Per-block IV
_kdfOutput      = new byte[64];       // KDF HMAC output
_aesKeyBuf      = new byte[32];       // Reusable AES key buffer
_hmacKeyBuf     = new byte[32];       // Reusable HMAC key buffer
_hmacOutput     = new byte[64];       // HMAC tag output
_hmacInput      = new byte[cap];      // One-shot HMAC input (max ~130K+)
_aes            = Aes.Create();       // Reusable AES instance
```

The `Aes` instance is created once and reused. The key is set via `_aes.Key = _aesKeyBuf`
using a pre-allocated buffer rather than calling `.ToArray()` on a span.

### 7.3 HMAC Input Assembly

The HMAC input is assembled in-place in the pre-allocated `_hmacInput` buffer by
`AssembleHmacInput()`. The layout for a block with 8-byte AAD (block index):

```
_hmacInput layout (total = 9 + 16 + ciphertextLength + 8):
  [0]           Algorithm byte (0x01)          ─┐
  [1..8]        AAD (8-byte block index, LE)    │ aeadAadLen = 9
  ──────────────────────────────────────────────┘
  [9..24]       IV (16 bytes)
  [25..N]       AES-CBC ciphertext (variable)
  [N+1..N+8]    adLen = aeadAadLen * 8 (big-endian, in bits = 72)
```

Note: `aeadAadLen` includes the algorithm prefix byte (1 + 8 = 9), matching R9's
computation. The `adLen` field is 72 bits (9 bytes * 8). This is verified by the
12 cross-compatibility tests that round-trip between R9 and OptimizedBlockCrypto.

### 7.4 Thread Safety

`OptimizedBlockCrypto` is **NOT** thread-safe. Each `BlockManager`, `ReadAheadBuffer`, and
`WriteBehindBuffer` creates its own instance, which is correct because `CipheredFileStream`
itself is not thread-safe (same as `FileStream`).

### 7.5 Disposal

On `Dispose()`, all sensitive buffers are zeroed with `Array.Clear()`:

```csharp
_aes.Dispose();
Array.Clear(_aeadKey);
Array.Clear(_kdfOutput);
Array.Clear(_hmacKeyBuf);
Array.Clear(_aesKeyBuf);
Array.Clear(_hmacInput);
Array.Clear(_hmacOutput);
Array.Clear(_iv);
Array.Clear(_kdfInput);
```

---

## 8. Performance Profiling Results

All numbers measured on production hardware. Crypto benchmarks use 256 MB of cache-cold data
pools to avoid L3 cache effects.

### 8.1 Decrypt Pipeline Breakdown (16K payload)

Measured by isolating each cryptographic primitive:

| Component               | us/call | % of Decrypt Pipeline |
|-------------------------|---------|-----------------------|
| KDF (HMAC-SHA512)       |  ~1.5   |             ~3.5%     |
| AES-256-CBC Decrypt     |  ~6.5   |            ~15.3%     |
| HMAC Auth Tag Verify    | ~34.5   |            ~81.2%     |
| **Total**               | ~42.5   |            100%       |

**The HMAC-SHA512 authentication tag computation dominates at ~81% of the pipeline.** This is
the irreducible bottleneck because SHA-512 has no hardware acceleration on x86 (unlike AES-NI
for AES). The KDF step uses the same HMAC-SHA512 primitive but on only 58 bytes of input, so it
is negligible. AES-256-CBC benefits from AES-NI hardware acceleration and is fast even at 16K.

### 8.2 OptimizedBlockCrypto vs R9 Throughput

Pure in-memory crypto benchmark (no IO), 256 MB data per test:

| Payload (bytes) | Block Size | Optimized Encrypt (MB/s) | R9 Encrypt (MB/s) | Encrypt Speedup | Optimized Decrypt (MB/s) | R9 Decrypt (MB/s) | Decrypt Speedup |
|-----------------|------------|--------------------------|--------------------|-----------------|--------------------------|--------------------|-----------------|
| 4,016           | 4K         | 226                      | 204                | 1.11x           | 286                      | 273                | 1.05x           |
| 8,112           | 8K         | 264                      | 257                | 1.02x           | 357                      | 341                | 1.05x           |
| 16,304          | 16K        | 282                      | 278                | 1.01x           | 396                      | 387                | 1.02x           |
| 32,688          | 32K        | 292                      | 295                | 0.99x           | 414                      | 416                | 0.99x           |
| 65,456          | 64K        | 271                      | 303                | 0.89x           | 428                      | 433                | 0.99x           |
| 130,992         | 128K       | 301                      | 307                | 0.98x           | 434                      | 439                | 0.99x           |

**Observations:**
- OptimizedBlockCrypto is faster at small block sizes due to lower allocation overhead.
- The speedup is most pronounced at small block sizes (1.05-1.11x at 4K-8K) where per-call
  allocation cost is a larger fraction of total work.
- At large block sizes (32K+), the crypto compute dominates and the difference narrows to
  ~1.0x. The key benefit is reduced GC pressure during sustained IO, not raw single-call speed.
- Throughput increases monotonically with block size because per-block fixed costs (49B overhead,
  KDF, HMAC finalization) are amortized over more payload bytes.

### 8.3 End-to-End Sequential IO Throughput (16K blocks)

Measured against raw `FileStream` baseline, 1 GB file, 64 KB caller buffer:

| Operation          | CipheredFileStream | Raw FileStream | Overhead |
|--------------------|--------------------|----------------|----------|
| Sequential Read    | ~356 MB/s          | ~2,500+ MB/s   | ~7x      |
| Sequential Write   | ~162 MB/s          | ~2,500+ MB/s   | ~15x     |

- **Sequential read at 356 MB/s achieves ~92% of the crypto ceiling** (~385 MB/s decrypt
  throughput at 16K). The remaining ~8% is IO overhead (disk reads, buffer management, position
  mapping).
- **Sequential write at 162 MB/s** is lower because each block requires both HMAC computation
  for authentication tagging (encrypt path) and SHA512 hashing for integrity tracking.
- Both read and write are CPU-bound on HMAC-SHA512, not IO-bound.

### 8.4 HMAC-SHA512: The Irreducible Bottleneck

HMAC-SHA512 dominates the pipeline because:

1. **No hardware acceleration.** AES has AES-NI (hardware instructions for AES rounds), but
   SHA-512 has no equivalent on current x86/x64 processors. SHA-256 has SHA-NI extensions on
   some CPUs, but SHA-512 does not.
2. **Used twice per block.** Once for the KDF (small input, negligible), and once for the
   authentication tag (processes the full ciphertext, ~16K+).
3. **Cannot be parallelized** within a single block -- the HMAC is a sequential hash chain.

The only way to improve throughput beyond the current ceiling is to:
- Use larger block sizes (amortize per-block HMAC overhead).
- Use a different AEAD scheme with hardware-accelerated authentication (e.g., AES-GCM with
  GHASH). However, this would break compatibility with the R9 crypto scheme.

---

## 9. Security Properties

### 9.1 What IS Guaranteed

| Property                      | Mechanism                                              |
|-------------------------------|--------------------------------------------------------|
| **Confidentiality**           | AES-256-CBC with per-block random IV and derived key   |
| **Per-block authentication**  | HMAC-SHA512 tag verified before decryption             |
| **Block reordering detection**| Block index included in AAD -- swapped blocks fail HMAC|
| **Tamper detection**          | Any modification to ciphertext, tag, or IV is detected |
| **Wrong key detection**       | HMAC verification fails immediately with wrong key     |
| **Key zeroing on dispose**    | Master key, derived keys, and all crypto buffers are zeroed via `Array.Clear` on `Dispose` |
| **Key isolation**             | Each `CipheredFileStream` makes a defensive copy of the key. Factory disposal does not affect active streams. |
| **File-level integrity**      | XOR of SHA512 hashes of all block ciphertexts stored in Protobuf header. Maintained through truncation via `RemoveBlock` for blocks whose hashes were cached (any block loaded via BlockManager or written via WriteBehindBuffer). |

### 9.2 What is NOT Guaranteed

| Non-property                       | Reason                                              |
|------------------------------------|-----------------------------------------------------|
| **Block truncation detection**     | An attacker could truncate the file to fewer blocks. The Protobuf header records `block_count`, but the header itself is in block 0 which the attacker controls (unless the integrity hash catches it). |
| **Hiding file size**               | The number and size of blocks reveals the approximate cleartext size. No length padding is applied beyond PKCS7 block alignment. |
| **Protection against key compromise** | If the master key is compromised, all data is accessible. Key management is delegated to `IKeyProvider`. |
| **Thread safety**                  | `CipheredFileStream` is not thread-safe, same as `FileStream`. |
| **Atomic writes**                  | A crash during write can leave partial blocks on disk. |

### 9.3 Verify-Before-Decrypt

The decrypt path **always verifies the HMAC authentication tag before performing AES decryption**.
This is critical for security:

```
Decrypt flow:
  1. Extract IV from ciphertext envelope
  2. Derive AEAD key via KDF
  3. Compute HMAC over [algo][AAD][IV][ciphertext][adLen]
  4. Compare computed HMAC with stored tag (fixed-time comparison)
  5. IF mismatch: return -1 (throw EncryptedFileCorruptException)
  6. ONLY IF match: decrypt with AES-256-CBC
```

This prevents padding oracle attacks and ensures that tampered ciphertext is never processed.

---

## 10. API Usage

### 10.1 Creating a New Encrypted File

```csharp
// Option 1: Direct key
byte[] key = new byte[32];
RandomNumberGenerator.Fill(key);

using var factory = new CipheredFileStreamFactory(key);
using Stream stream = factory.Create("data.enc", FileMode.Create);

stream.Write(data, 0, data.Length);
// Flush + dispose handles header writeback
```

### 10.2 Reading an Existing Encrypted File

```csharp
using var factory = new CipheredFileStreamFactory(key);
using Stream stream = factory.Create("data.enc", FileMode.Open, FileAccess.Read);

byte[] buffer = new byte[65536];
int bytesRead;
while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
{
    // Process decrypted data
}
```

### 10.3 Using an Ephemeral Key Provider

```csharp
using var keyProvider = new EphemeralKeyProvider();
using var factory = new CipheredFileStreamFactory(keyProvider);

using Stream stream = factory.Create("temp.enc", FileMode.Create);
stream.Write(payload, 0, payload.Length);
// Key is cryptographically random and zeroed on keyProvider.Dispose()
```

### 10.4 Configuring Block Size and Access Pattern

```csharp
using var factory = new CipheredFileStreamFactory(key);

var options = new CipheredFileStreamOptions
{
    BlockSize = BlockSizeOption.Block32K,           // 32K blocks
    AccessPattern = AccessPattern.Sequential,       // Ring buffers (default)
    BufferSize = 2 * 1024 * 1024,                   // 2MB ring buffer
};

using Stream stream = factory.Create("large.enc", FileMode.Create, options);
```

### 10.5 Random Access Pattern

```csharp
var options = new CipheredFileStreamOptions
{
    AccessPattern = AccessPattern.RandomAccess,     // Single-block cache
};

using Stream stream = factory.Create("db.enc", FileMode.Open, FileAccess.ReadWrite, options);

// Seek and read/write at arbitrary positions
stream.Seek(1024 * 1024, SeekOrigin.Begin);
stream.Write(patch, 0, patch.Length);

stream.Seek(0, SeekOrigin.Begin);
stream.Read(header, 0, header.Length);
```

### 10.6 Standard Stream Operations

```csharp
using Stream stream = factory.Create("file.enc", FileMode.Create);

// All standard Stream operations work:
stream.Write(data, 0, data.Length);
stream.Position = 0;
stream.Read(buf, 0, buf.Length);
stream.Seek(-100, SeekOrigin.End);
stream.SetLength(500);
stream.Flush();

long len = stream.Length;    // Cleartext length
long pos = stream.Position;  // Cleartext position
bool canR = stream.CanRead;
bool canW = stream.CanWrite;
bool canS = stream.CanSeek;
```
