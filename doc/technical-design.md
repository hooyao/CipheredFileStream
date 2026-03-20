# CipheredFileStream - Technical Design

## 1. Overview

CipheredFileStream is a `Stream` implementation that provides transparent AES-GCM encryption for files. It serves as a drop-in replacement for `FileStream`, encrypting data before writing to disk and decrypting on read. The design prioritizes:

- **Drop-in replacement** -- any code that works with `Stream` works with `CipheredFileStream`
- **Random access performance** via chunked storage (all chunks same physical size)
- **Data integrity** via AES-GCM authentication tags (per-chunk)
- **File integrity** via XOR checksum (file-level)
- **Format identification** via cleartext magic number (readable without key)
- **Security** via AAD binding (block reordering detection)

## 2. File Format (v1)

Format version: `0x0001`. Magic bytes: `0x43 0x49 0x50 0x48 0x45 0x52 0x45 0x44` (ASCII `"CIPHERED"`).

### 2.1 Physical Layout

```
+--------+--------+--------+--------+--------+--------+---
|Chunk 0 |Chunk 1 |Chunk 2 |Chunk 3 |  ...   |Chunk N |
|        |        |        |        |        |        |
+--------+--------+--------+--------+--------+--------+---
<-CS----> <-CS----> <-CS----> <-CS---->         <-CS---->

CS = Chunk Size (configurable: 4K, 8K, 16K, 32K, 64K, 128K)
All chunks are the same physical size.
```

### 2.2 Chunk 0 — Complete Structure

Chunk 0 contains the file header and user data:

**On-disk layout:**

```
CHUNK 0 — ON DISK (ChunkSize bytes)
┌──────────────────┬────────────┬──────────────────────────────┬──────────┐
│ Cleartext Header │  CT Length │        Ciphertext            │ Padding  │
│     8 bytes      │  4 bytes   │  (encrypted envelope)        │ (zeros)  │
│   UNENCRYPTED    │  uint32 LE │                              │          │
└──────────────────┴────────────┴──────────────────────────────┴──────────┘
│← byte [0..7] ──→│←[8..11]──→│←── [12..N] ────────────────→│←to CS──→│
```

**Cleartext header (bytes 0-7, readable without key):**

```
Offset  Size  Field                    Value
------  ----  -----------------------  ---------------------------
0       8B    Magic bytes              "CIPHERED" (ASCII)
```

**Encrypted payload (after decryption):**

```
DECRYPTED PAYLOAD
┌────────────┬─────────────────────────────┬─────────────────────────────┐
│ Hdr Len 2B │   Protobuf Header (fixed)   │         User Data           │
│  uint16 LE │       (≤128 bytes)           │                             │
└────────────┴─────────────────────────────┴─────────────────────────────┘
```

The Protobuf header is padded to a fixed size (128 bytes max) to ensure the user data offset is constant. This prevents header size changes from shifting chunk positions.

### 2.3 Chunk N (N ≥ 1)

Middle chunks are simpler — no cleartext header, no Protobuf overhead.

```
CHUNK N — ON DISK (ChunkSize bytes)
┌────────────┬──────────────────────────────────────┬────────────────────┐
│  CT Length  │              Ciphertext              │      Padding       │
│  4 bytes    │        (encrypted envelope)          │      (zeros)       │
│  uint32 LE  │                                      │                    │
└────────────┴──────────────────────────────────────┴────────────────────┘
│← [0..3] ─→│←──── [4..N] ───────────────────────→│←── to ChunkSize ─→│
```

After decryption, the entire payload is user data.

### 2.4 Last Chunk — Partial Data

The last chunk is physically identical to any other chunk (same ChunkSize). However, it may only be partially filled with real user data:

```
LAST CHUNK — DECRYPTED PAYLOAD
┌──────────────────────────────────┬─────────────────────────────────────┐
│          Real User Data          │          Zero Padding               │
│          (K bytes)               │    (PayloadCapacity - K bytes)      │
└──────────────────────────────────┴─────────────────────────────────────┘
│←── meaningful data ────────────→│←── zeros, encrypted but ignored ──→│
```

The entire chunk is always encrypted — the ciphertext size is constant regardless of how much real data the chunk holds. An observer cannot tell whether the last chunk contains 1 byte or is completely full.

### 2.5 Header (Protobuf)

```protobuf
syntax = "proto3";

message FileHeader {
  ChunkSize chunk_size = 1;
  bytes master_nonce = 2;      // 12 bytes, unique per file
  KeyInfo key_info = 3;
  bytes total_checksum = 4;    // XOR of all chunk checksums (32 bytes)
}

enum ChunkSize {
  CHUNK_SIZE_4K = 0;    // 4096 bytes
  CHUNK_SIZE_8K = 1;    // 8192 bytes
  CHUNK_SIZE_16K = 2;   // 16384 bytes
  CHUNK_SIZE_32K = 3;   // 32768 bytes
  CHUNK_SIZE_64K = 4;   // 65536 bytes
  CHUNK_SIZE_128K = 5;  // 131072 bytes
}

message KeyInfo {
  KeyDerivation method = 1;
  bytes salt = 2;          // for password-based derivation
  uint32 iterations = 3;   // for PBKDF2
}

enum KeyDerivation {
  KEY_DERIVATION_NONE = 0;     // raw key provided
  KEY_DERIVATION_PBKDF2 = 1;
}
```

**Note:** `plaintext_length` and `chunk_count` are stored as fixed-size binary fields (12 bytes) after the Protobuf header, not inside Protobuf. This ensures the Protobuf header size never changes, avoiding chunk position shifts.

## 3. Encryption Details

### 3.1 Algorithm

- **Cipher**: AES-256-GCM (Galois/Counter Mode)
- **Key size**: 256 bits (32 bytes)
- **Nonce size**: 96 bits (12 bytes)
- **Tag size**: 128 bits (16 bytes)
- **Padding**: None (AES-GCM is a stream cipher mode)
- **Hardware acceleration**: GHASH is accelerated via PCLMULQDQ instruction on modern CPUs

### 3.2 Why AES-GCM

AES-GCM provides both encryption and authentication in a single operation:

| Feature | AES-CBC + HMAC-SHA512 | AES-GCM |
|---------|----------------------|---------|
| Encryption | AES-CBC | AES-CTR |
| Authentication | HMAC-SHA512 | GHASH (built-in) |
| HW acceleration | AES-NI only | AES-NI + PCLMULQDQ |
| Separate MAC needed | Yes | No |
| Verify-before-decrypt | Required | Built-in |
| Complexity | Higher | Lower |

AES-GCM is faster because GHASH has hardware acceleration, while HMAC-SHA512 does not.

### 3.3 Key Management

Two modes:

1. **Raw key**: User provides 32-byte key directly
2. **Password-based (PBKDF2)**:
   - Derive key from password
   - Salt: 16 bytes, stored in header
   - Iterations: configurable (default 600,000)
   - Hash: SHA-256

### 3.4 Chunk Authentication

- Each chunk is independently authenticated via AES-GCM tag
- **AAD (Additional Authenticated Data)**: `chunk_index` (uint32, little-endian)
- AAD binds each chunk to its position → swapping chunks detects tampering
- Tamper detection at read: if tag verification fails, throw `CryptographicException`

**Why AAD with chunk index works:**
```
Chunk 0 encrypted with AAD=0
Chunk 1 encrypted with AAD=1
...

If chunk 0 and chunk 1 are swapped:
  - Read at position 0 → decrypt chunk 1 with AAD=0 → tag mismatch (was encrypted with AAD=1)
  - Read at position 1 → decrypt chunk 0 with AAD=1 → tag mismatch (was encrypted with AAD=0)
```

### 3.5 Integrity Verification (XOR Checksum)

**Problem**: AES-GCM per-chunk auth cannot detect:
- File-level corruption (truncation, extra chunks)

**Solution**: XOR total checksum

**Chunk Checksum:**
- Algorithm: SHA-256
- Input: `nonce (12) + ciphertext + auth_tag (16)`
- Computed: each time chunk is written

**Total Checksum (XOR):**
- Algorithm: XOR all chunk checksums
- `total = C0 XOR C1 XOR C2 XOR ... XOR CN`
- Stored: in header `total_checksum` field (32 bytes)
- Update O(1): `total = total XOR old_Ci XOR new_Ci`

**Why XOR:**
- O(1) update (vs O(n) for sequential hash)
- Order-independent (commutative)
- Detects any chunk modification

**Update Flow:**
```
1. Compute chunk_checksum = SHA256(nonce + ciphertext + tag)
2. Write chunk to disk
3. Update total: header.total_checksum ^= chunk_checksum
4. Write header
```

**Verification Flow (open file):**
```
1. Read header, get total_checksum
2. Compute actual_total = XOR of all chunk checksums
3. Verify: total_checksum == actual_total
   → fails: file corrupted (chunks missing, added, or damaged)
4. On each chunk read:
   a. AES-GCM decrypt with AAD=chunk_index → fails if swapped/tampered
```

## 4. Random Access

### 4.1 Seek Operation

```
chunk_index = position / chunk_size
chunk_offset = position % chunk_size
```

### 4.2 File Position Mapping

For plaintext position `P`:

- **Chunk index**: `P / chunk_size`
- **Offset within chunk**: `P % chunk_size`
- **File position of chunk**: `chunk_index * chunk_total_size`
  - Where `chunk_total_size = chunk_size` (all chunks same physical size)

### 4.3 Chunk Size Table

| Chunk Size | Physical Size | Payload Capacity | Overhead |
|------------|---------------|------------------|----------|
| 4K | 4,096 B | 4,048 B | 48 B (1.2%) |
| 8K | 8,192 B | 8,144 B | 48 B (0.6%) |
| 16K | 16,384 B | 16,336 B | 48 B (0.3%) |
| 32K | 32,768 B | 32,720 B | 48 B (0.1%) |
| 64K | 65,536 B | 65,488 B | 48 B (0.07%) |
| 128K | 131,072 B | 131,024 B | 48 B (0.04%) |

Overhead per chunk: 12 (nonce) + 16 (tag) + 4 (length prefix) = 32 bytes + AES-GCM padding

### 4.4 Why 16K is Recommended Default

- **Crypto efficiency**: Larger chunks amortize per-chunk overhead
- **Memory footprint**: 1MB buffer holds ~64 chunks at 16K
- **Random access**: 16K is reasonable read amplification for single-byte reads
- **Performance**: ~92% of theoretical crypto throughput ceiling

## 5. Public API

### 5.1 CipheredFileStream Class

```csharp
/// <summary>
/// A Stream implementation that provides transparent AES-GCM encryption for files.
/// Files are encrypted and stored in chunks for efficient random access.
/// </summary>
public sealed class CipheredFileStream : Stream
{
    // Construction with raw key
    public CipheredFileStream(
        string path,
        FileMode mode,
        FileAccess access,
        ReadOnlySpan<byte> key,
        ChunkSize chunkSize = ChunkSize.Size4K);

    // Construction with password
    public CipheredFileStream(
        string path,
        FileMode mode,
        FileAccess access,
        ReadOnlySpan<char> password,
        ChunkSize chunkSize = ChunkSize.Size4K);

    // Stream overrides
    public override bool CanRead { get; }
    public override bool CanSeek { get; }
    public override bool CanWrite { get; }
    public override long Length { get; }        // Plaintext length
    public override long Position { get; set; }

    public override int Read(byte[] buffer, int offset, int count);
    public override int Read(Span<byte> buffer);
    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer, CancellationToken cancellationToken = default);

    public override void Write(byte[] buffer, int offset, int count);
    public override void Write(ReadOnlySpan<byte> buffer);
    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default);

    public override long Seek(long offset, SeekOrigin origin);
    public override void Flush();
    public override Task FlushAsync(CancellationToken cancellationToken);
    public override void SetLength(long value);

    // Integrity verification
    public void VerifyIntegrity();

    // Disposal
    protected override void Dispose(bool disposing);
    public override ValueTask DisposeAsync();
}

public enum ChunkSize
{
    Size4K = 4096,
    Size8K = 8192,
    Size16K = 16384,
    Size32K = 32768,
    Size64K = 65536,
    Size128K = 131072
}
```

### 5.2 Open Modes

| FileMode | FileAccess | Behavior |
|----------|-----------|----------|
| Create | Write | Create new file, overwrite if exists |
| CreateNew | Write | Create new file, fail if exists |
| Open | Read | Open existing, read-only |
| OpenOrCreate | ReadWrite | Open or create |
| Append | Write | Open at end, write only |

## 6. Buffering & Performance

### 6.1 Buffer Pool

- Use `ArrayPool<byte>.Shared` for chunk buffers
- Pre-allocate all crypto buffers in constructor (avoid GC pressure)
- Avoid allocations in hot paths (Read/Write loops)

### 6.2 Cache Strategy

- Cache current chunk in memory (single-block cache)
- On seek to different chunk: decrypt and cache new chunk
- Write-back: flush cached chunk before loading new one

### 6.3 Performance Characteristics

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Sequential read | O(n) | Single decryption per chunk |
| Random read | O(1) | One chunk decryption per seek |
| Sequential write | O(n) | Single encryption per chunk |
| Random write | O(1) | Read-modify-write for partial chunk |
| Seek | O(1) | Position calculation only |
| Integrity update | O(1) | XOR of chunk checksums |

### 6.4 AES-GCM Performance

AES-GCM benefits from hardware acceleration:
- **AES-NI**: Hardware AES encryption/decryption
- **PCLMULQDQ**: Hardware GHASH authentication
- **Combined**: ~400-500 MB/s throughput on modern CPUs

Compared to AES-CBC + HMAC-SHA512 (~350 MB/s), AES-GCM is ~20-30% faster due to hardware-accelerated authentication.

## 6. Error Handling

### 6.1 Exceptions

| Exception | Condition |
|-----------|-----------|
| `ArgumentException` | Invalid chunk size, key length |
| `ArgumentNullException` | Null key/password |
| `FileNotFoundException` | File not found on Open |
| `InvalidOperationException` | Wrong FileMode for operation |
| `ObjectDisposedException` | Access after disposal |
| `CryptographicException` | AES-GCM auth failed (tampered/swapped chunk) |
| `InvalidDataException` | Total checksum mismatch (file integrity failure) |
| `EndOfStreamException` | Read beyond end |
| `IOException` | Underlying I/O errors |

### 6.2 Tamper Detection

When reading a chunk:
1. Derive expected nonce from chunk index
2. Attempt AES-GCM decryption with AAD = chunk_index
3. If tag verification fails → throw `CryptographicException`
   - Chunk data tampered, or chunk swapped to different position

### 6.3 Full File Verification

When opening a file:
1. Read header, get total_checksum
2. For each chunk, compute `SHA256(nonce + ciphertext + tag)`, XOR into running total
3. Verify: `total_checksum == computed_total`
4. If mismatch → throw `InvalidDataException` (chunks missing, added, or corrupted)

## 7. Security Properties

### 7.1 What IS Guaranteed

| Property | Mechanism |
|----------|-----------|
| **Confidentiality** | AES-256-GCM with per-chunk nonce |
| **Per-chunk authentication** | AES-GCM tag (128-bit) |
| **Chunk reordering detection** | AAD = chunk_index (swapped chunks fail auth) |
| **Tamper detection** | Any modification to ciphertext/nonce/tag is detected |
| **Wrong key detection** | GCM auth fails immediately with wrong key |
| **File-level integrity** | XOR of SHA-256 chunk checksums |
| **Key zeroing on dispose** | Sensitive buffers cleared via `Array.Clear` |

### 7.2 What is NOT Guaranteed

| Non-property | Reason |
|--------------|--------|
| **File truncation detection** | Attacker could remove trailing chunks (chunk_count in header helps but header itself could be modified) |
| **Hiding file size** | Number of chunks reveals approximate size |
| **Thread safety** | Not thread-safe, same as `FileStream` |
| **Atomic writes** | Crash during write can leave partial state |

### 7.3 Why AES-GCM is Secure

AES-GCM provides built-in verify-before-decrypt:
1. GHASH computes authentication tag over ciphertext + AAD
2. Tag is compared before decryption begins
3. If tag mismatch, decryption is never attempted
4. This prevents padding oracle and chosen-ciphertext attacks

No separate verify step needed — it's built into the algorithm.

## 8. Thread Safety

- **Not thread-safe** by default (matches `FileStream` behavior)
- Concurrent reads from different instances: safe (OS file sharing)
- Concurrent read+write: undefined behavior, caller must synchronize

## 9. Future Considerations

- Factory pattern (`CipheredFileStreamFactory`) for cleaner API
- Sequential mode with ring buffers for bulk IO
- Random access mode with single-block cache
- Compression before encryption (opt-in)
- Key rotation without re-encrypting entire file
- Ephemeral key provider for temporary files
