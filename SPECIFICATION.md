# Streaming-LZMA Archive Format Specification

Version 1.0

## 1. Introduction

### 1.1 Purpose

This document specifies the Streaming-LZMA archive format, a container format for LZMA-compressed data designed for
streaming operation, parallel processing, and robust data integrity verification.

### 1.2 Theory of Operation

The Streaming-LZMA format addresses practical requirements in modern data archival and transmission:

**Streaming Operation**: The format can be written and read sequentially without seeking, enabling use in pipelines,
network streams, and tape storage systems. Writers do not need to know the total data size or block count before
beginning compression.

**Parallel Processing**: Data is organized in independent blocks that can be decompressed concurrently. Block boundaries
are discoverable without parsing the entire file, enabling efficient multithreaded operation.

**Data Integrity**: Multiple validation layers protect against corruption. The format employs Blake3 hashing for content
verification and Reed-Solomon error correction codes to protect the hash itself against corruption. This dual approach
guards against both random and systematic errors.

**Appendability**: New data can be appended to existing archives by overwriting the end-of-blocks marker, enabling
incremental backups and log aggregation use cases.

**Simplicity**: The format uses fixed-size fields where practical and avoids unnecessary complexity. All multibyte
integers use little-endian encoding. No alignment padding is required.

### 1.3 Conventions

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC 2119.

Byte values are shown in hexadecimal notation (e.g., 0xFE). Multibyte sequences are shown with the first byte leftmost.

## 2. File Structure

A Streaming-LZMA file consists of three sections:

```
+==================+
|      Header      |  (Variable: 6-10 bytes)
+==================+
|      Blocks      |  (Variable: 1 or more blocks)
+==================+
|     Trailer      |  (Fixed: 80 bytes)
+==================+
```

## 3. Header Format

The header contains format identification and compression configuration:

```
+------+------+------+------+
| 0xFE | 0xDC | 0xBA | 0x98 |  Magic bytes (4 bytes)
+------+------+------+------+
|    Version   |   Config   |  Version and configuration (2 bytes)
+------+------+------+------+
|  Compression Properties   |  (1-2 bytes, algorithm-specific)
+---------------------------+
|   Prefilter Properties    |  (0-1 bytes, filter-specific)
+---------------------------+
```

### 3.1 Magic Bytes

The file begins with the four-byte sequence 0xFE 0xDC 0xBA 0x98. This sequence:

- Is not valid UTF-8
- Contains no printable ASCII characters
- Provides strong file type identification

Decoders MUST verify these bytes before processing.

### 3.2 Version

One byte indicating the format version. This specification defines version 0x01.

Decoders MUST reject files with unsupported version numbers.

### 3.3 Configuration

One byte containing compression algorithm and prefilter selection:

- Bits 0-2: Compression algorithm
    - 0x00: LZMA
    - 0x01: LZMA2
    - 0x02-0x07: Reserved

- Bits 3-7: Prefilter
    - 0x00: No prefilter
    - 0x01: Delta
    - 0x02: BCJ x86
    - 0x03: BCJ ARM
    - 0x04: BCJ ARM Thumb
    - 0x05: BCJ ARM64
    - 0x06: BCJ SPARC
    - 0x07: BCJ PowerPC
    - 0x08: BCJ IA64
    - 0x09: BCJ RISC-V
    - 0x0A-0x1F: Reserved

### 3.4 Compression Properties

Algorithm-specific compression parameters:

**LZMA** (2 bytes):

- Byte 0: Properties byte encoding (pb * 5 + lp) * 9 + lc
    - lc: number of literal context bits (0-8)
    - lp: number of literal position bits (0-4)
    - pb: number of position bits (0-4)
- Byte 1: Dictionary size as power of 2 (size = 2^(n+12))

**LZMA2** (1 byte):

- Byte 0: Dictionary size as power of 2 (size = 2^(n+12))

Valid dictionary sizes range from 4 KiB (n=0) to 4 GiB (n=20).

### 3.5 Prefilter Properties

Filter-specific configuration parameters:

**Delta filter** (1 byte):

- Byte 0: Distance minus 1 (0x00 represents distance 1, 0xFF represents distance 256)

**BCJ filters**: No additional properties (offset is always 0)

## 4. Blocks Section

The blocks section contains any number of compressed blocks followed by an end marker:

```
+---------------------+--------------------+
| Block 0 Size (4B)   | Block 0 Data       |
+---------------------+--------------------+
| Block 1 Size (4B)   | Block 1 Data       |
+---------------------+--------------------+
|         ...         |       ...          |
+---------------------+--------------------+
| 0x00 0x00 0x00 0x00 | (End-of-blocks)    |
+------------------------------------------+
```

### 4.1 Block Format

Each block consists of:

- **Size** (4 bytes): Compressed size of the block data in bytes, stored as little-endian uint32
- **Data**: Compressed data stream

Block properties:

- Minimum size: 1 B         (size field value 0x00000001)
- Maximum size: 4 GiB - 1 B (size field value 0xFFFFFFFF)
- Zero-length blocks are not permitted
- Files larger than 4 GiB - 1 B MUST be split across multiple blocks

**Block Independence**: Each block is completely independent:

- LZMA/LZMA2 encoder state is reset for each block (fresh dictionary, reset probability models)
- Prefilters (if used) are reset for each block with no state carried between blocks
- BCJ filters compute jumps/calls relative to the block start, not the file start
- No compression dictionary or filter state is shared between blocks

**LZMA/LZMA2 Stream Format**:

- **LZMA**: Raw LZMA stream data without end-of-stream marker (block size provides boundary)
- **LZMA2**: Raw LZMA2 chunk stream, terminated by block boundary

### 4.2 Block Size Recommendations

**Compression Ratio Trade-offs**:

The choice of block size directly impacts compression ratio:

- **Single block** (block size = file size): Maximum compression ratio, no parallelization possible
- **Multiple blocks**: Reduced compression ratio due to dictionary reset at block boundaries, but enables parallel
  processing

The compression penalty occurs because:

1. Each block starts with an empty dictionary, losing context from previous data
2. Repeated patterns across block boundaries cannot be exploited
3. Prefilters reset their state, potentially missing optimization opportunities at boundaries

**Optimal configuration**:

- Block size should be ≥ dictionary size for efficient compression
- When block size < dictionary size, the dictionary cannot be fully utilized
- When block size >> dictionary size, diminishing returns on compression benefit

**Recommended defaults**:

- For maximum compression: Use a single block
- For streaming with moderate parallelism: 16-64 MiB blocks
- For high parallelism: 1-16 MiB blocks (accepting compression ratio penalty)

**Memory usage considerations**:
Parallel decompression requires approximately (dict_size + block_size) × thread_count memory. For example,
512 MiB blocks and 256 MiB dictionary with 8 threads requires 6144 MiB RAM minimum. Implementations SHOULD document
memory requirements and provide configuration options.

### 4.3 End-of-Blocks Marker

The sequence 0x00 0x00 0x00 0x00 indicates the end of blocks. Since zero-length blocks are invalid, this sequence
unambiguously marks the end of the blocks section.

## 5. Trailer Format

The trailer provides integrity verification and metadata:

```
+---------------------+
| Uncompressed Size   |  (8 bytes, little-endian)
+---------------------+
| Compressed Size     |  (8 bytes, little-endian)
+---------------------+
| Blake3 Hash         |  (32 bytes)
+---------------------+
| Reed-Solomon Parity |  (32 bytes)
+---------------------+
```

### 5.1 Size Fields

**Uncompressed Size**: Total size of decompressed data in bytes (informational)
**Compressed Size**: Total size of all compressed blocks in bytes (informational)

These fields are provided for informational purposes only. They are protected against corruption by their position
before the RS-protected hash, but they are not included in the hash calculation and thus not authenticated.
Implementations MUST NOT rely on these fields for security decisions or buffer allocation without independent
validation.

The compressed size represents the size of the concatenated block data (without the block sizes).
The uncompressed size represents the size of the concatenated uncompressed data.

### 5.2 Blake3 Hash

A 256-bit Blake3 hash computed over the concatenated uncompressed data of all blocks in order.

### 5.3 Reed-Solomon Error Correction

32 bytes of Reed-Solomon parity data protecting the Blake3 hash.

Parameters:

- Field: GF(2^8)
- Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
- Code: (n=64, k=32, t=16)
- Generator: α = 2

**Encoding**: The 32-byte Blake3 hash is treated as a sequence of 32 consecutive bytes [h₀, h₁, ..., h₃₁] for
Reed-Solomon encoding. No byte reordering or integer interpretation is performed.

The code can correct up to 16 byte errors in the hash field.

Reed-Solomon codes were chosen for their exceptional maturity and proven reliability. They have been successfully
deployed for decades in CD/DVD error correction, QR codes, satellite communications, and RAID systems. The mathematics
are thoroughly understood and battle-tested implementations are available.

## 6. Processing Requirements

### 6.1 Compression

1. Write header with appropriate configuration
2. For each block of input data:
    - Compress the block
    - Write 4-byte size (little-endian)
    - Write compressed data
3. Write end-of-blocks marker (0x00000000)
4. Calculate Blake3 hash of all uncompressed data
5. Calculate Reed-Solomon parity of Blake3 hash
6. Write trailer

### 6.2 Decompression

1. Verify magic bytes
2. Verify version compatibility
3. Parse compression and filter configuration
4. For each block until end-of-blocks marker:
    - Read 4-byte size
    - If size is 0x00000000, end block processing
    - Decompress block data
    - Append to output
5. Compute Blake3 hash of decompressed data
6. Verify hash against trailer (optionally using Reed-Solomon correction)

### 6.3 Appending

To append data to an existing archive:

1. Seek to final end-of-blocks marker
2. Overwrite with new blocks
3. Write new end-of-blocks marker
4. Recalculate and write new trailer

### 6.4 Recovery Philosophy

**The format explicitly chooses complete verification over partial recovery**.
These goals are fundamentally incompatible:

- **Hash verification** requires all data to be intact
- **Partial recovery** produces incomplete data that cannot match the original hash

Streaming-LZMA prioritizes cryptographic verification of complete data integrity.
Users requiring recovery capabilities should use external error recovery systems (for example PAR2).

This design choice reflects the reality that most users need either fully correct data or clear failure indication, not
partially corrupted results.

## 7. Validation Strategy

The format provides multiple validation layers:

1. **Block Level**: LZMA/LZMA2 stream integrity checking detects most corruption within compressed data
2. **Format Level**: End-of-blocks marker validates structural integrity
3. **Content Level**: Blake3 hash verifies complete data integrity
4. **Trailer Level**: Reed-Solomon codes protect against hash corruption and provide strong end-of-file validation

## 8. Error Handling

### 8.1 Fatal Errors

Decoders MUST abort on:

- Invalid magic bytes
- Unsupported version
- Invalid configuration values

### 8.2 Integrity Errors

Decoders MUST report integrity failures for:

- LZMA/LZMA2 stream corruption
- Blake3 hash mismatch (after Reed-Solomon correction attempt)
- Reed-Solomon decode failure (uncorrectable errors)

### 8.3 Recovery Limitations

**The format explicitly does not support partial recovery after corruption**. This is a deliberate design choice:

- Integrity verification requires the complete data to compute the Blake3 hash
- Partial recovery would produce data that cannot be verified against the stored hash
- Block boundaries after corruption are generally unrecoverable due to the lack of synchronization markers

While decoders SHOULD attempt Reed-Solomon correction of a corrupted Blake3 hash (up to 16 bytes), the format
prioritizes complete data integrity over partial recovery. Users requiring recovery capabilities should employ
external error recovery systems (e.g., PAR2) or redundant storage.

## 9. Security Considerations

### 9.1 Memory Safety

- Decoders MUST NOT trust size fields for memory allocation without validation
- Decoders MUST prevent integer overflow in size calculations
- Decoders MUST validate block sizes before allocation

### 9.2 Resource Limits

- Decoders SHOULD implement configurable memory usage limits
- Parallel decoders SHOULD limit thread pool size

### 9.3 Cryptographic Considerations

- Blake3 provides 128-bit collision resistance and 256-bit preimage resistance
- The format does not provide encryption or authentication
- The format does not protect against intentional tampering without an outside
  communication channel for the authentication of the hash value

## 10. Implementation Notes

### 10.1 Streaming Operation

The format supports full streaming operation:

- Compression without knowing final size
- Decompression without seeking
- Pipe-friendly operation

### 10.2 Parallel Processing

For parallel decompression:

1. Parse all block sizes sequentially
2. Assign blocks to worker threads
3. Concatenate results in order
4. Hash can be calculated either while or after
   writing the uncompressed output data

## 11. Design Rationale and Critical Analysis

This section addresses potential criticisms of the Streaming-LZMA format design and explains the reasoning behind key
architectural decisions.

### 11.1 Trailing Metadata Vulnerability

**Criticism**: Placing critical integrity data (Blake3 hash) in a trailer makes the format vulnerable to truncation
attacks. A leading integrity check would detect truncation immediately.

**Response**: While trailing metadata does have truncation vulnerability, our design mitigates this through multiple
mechanisms:

1. **End-of-blocks marker** (0x00000000) provides early truncation detection before reaching the trailer
2. **Reed-Solomon protection** specifically guards against trailer corruption, allowing recovery from up to 16 bytes of
   damage
3. **Streaming requirement**: Leading checksums require either knowing the data size in advance or using chunked
   verification, both of which complicate streaming operation

The trailer design was chosen to maintain pure streaming capability - writers can begin compression without knowing the
final size, and readers can begin decompression immediately upon receiving data.

### 11.2 Cryptographic Hash "Overkill"

**Criticism**: CRC32 is sufficient for error detection in compressed formats. Cryptographic hashes add unnecessary
complexity and computational overhead without meaningful benefit for integrity checking.

**Response**: Blake3 was chosen not for a single purpose but as a multipurpose tool that justifies its inclusion:

**Performance**: Modern Blake3 implementations with SIMD support achieve ~7 GiB/s on current hardware, actually
*exceeding* CRC32 performance (~3-4 GiB/s) while providing cryptographic security.

**Multiple Use Cases**:

- **Content addressing**: The hash serves as a globally unique identifier for deduplication systems
- **Out-of-band verification**: Users can transmit the hash separately for independent validation
- **Audit trails**: Provides cryptographic proof of file contents for compliance and legal requirements
- **Tamper detection**: Detects intentional manipulation, not just accidental corruption

### 11.3 Reed-Solomon Complexity

**Criticism**: Error correction codes add implementation complexity for minimal practical benefit. Most users either
have uncorrupted files or completely corrupted files - partial correction is rarely useful.

**Response**: The Reed-Solomon layer serves a unique purpose beyond simple error correction - it creates what we term
the "fourth factor" of integrity:

**Mathematical Certainty**: Traditional formats rely on three factors:

1. Decompression success
2. Checksum match
3. Size validation

Streaming-LZMA adds a fourth: the Blake3 hash must form a valid Reed-Solomon codeword. For undetected corruption to
occur, following fail states have to occur:

1. Corruption of data
2. Corruption of hash and Blake3 hash collision (2^-256 probability)
3. Corrupted hash still forms a valid RS codeword (2^-128 probability)

This combined probability (~2^-384) makes undetected corruption astronomically unlikely.

**Format Validation**: A valid RS codeword provides instant confirmation that we're reading an actual Streaming-LZMA
file, not random data or a different format. This is particularly valuable for recovery tools and format detection.

**Trailer Protection**: While we chose trailing metadata for streaming compatibility, RS codes specifically protect
against the vulnerability this creates. The 16-byte correction capability can recover from common data corruption
patterns.

### 11.4 Lack of Random Access

**Criticism**: The format doesn't support efficient random access to arbitrary positions in the uncompressed data,
limiting its utility for large archives.

**Response**: This is a deliberate trade-off for simplicity and streaming capability:

- **Block independence** enables parallel decompression and partial access to block boundaries
- **Sequential scan** can build an index in a single pass for subsequent random access
- **Simplicity benefit**: Random access would require either fixed-size blocks (reducing compression) or an index
  (adding complexity)

Applications requiring true random access should use formats designed for that purpose (e.g., indexed containers) or
build external indices.

### 11.6 Summary

The Streaming-LZMA format makes deliberate trade-offs, prioritizing:

- **Streaming operation** over random access
- **Mathematical integrity guarantees** over minimal complexity
- **Predictable behavior** over maximum flexibility
- **Future-proof security** over minimal overhead

These choices result in a format that may not be optimal for every use case but excels at its intended purpose:
reliable, streaming compression with exceptional integrity assurance. The combination of Blake3 hashing with
Reed-Solomon protection provides a level of corruption detection and recovery that exceeds both simpler formats
(like LZIP) and more complex ones (like XZ), while maintaining reasonable implementation complexity.

## 12. Acknowledgements

The Streaming-LZMA format builds upon decades of compression research and development. We acknowledge:

- **Igor Pavlov** for creating the LZMA algorithm and LZMA2 format, which form the compression foundation of this
  specification
- **Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko** for developing the Blake3 hash function
- **Irving S. Reed and Gustave Solomon** for their pioneering work on error correction codes
- **The XZ Utils project** (Lasse Collin and contributors) for advancing LZMA-based compression formats
- **The lzip project** (Antonio Diaz Diaz) for demonstrating the value of simplicity in compression format design
- The broader compression community for continuous innovation in data compression techniques

## 13. Intellectual Property Notice

### 13.1 Specification License

This specification is placed in the **public domain**. Anyone may freely implement, use, modify, or distribute this
specification without restriction.

### 13.2 Patent Disclaimer

To the best of the authors' knowledge, the Streaming-LZMA format as specified in this document is not encumbered by
patents. However:

- LZMA and LZMA2 algorithms are believed to be patent-free and have been widely implemented without patent claims for
  over 20 years
- Blake3 is explicitly released under CC0 (public domain) with no known patent encumbrances
- Reed-Solomon codes have been in public use since 1960 with expired foundational patents
- BCJ filters and Delta encoding are well-established techniques without known patent claims

**This document does not constitute legal advice**. Implementers are responsible for their own patent review and risk
assessment. The authors make no warranties regarding patent status and assume no liability for implementations based
on this specification.

### 13.3 Trademark Notice

"Streaming-LZMA" is not a registered trademark. The name may be used freely to identify implementations of this
specification.

## Appendix A: Test Vectors

### A.1 Minimal File

Hexdump of a minimal Streaming-LZMA file using LZMA + no prefilter and no content:

```
|fedcba98 01005d06 00000000 00000000| ......]......... 00000000
|00000000 00000000 00000000 af1349b9| ..............I. 00000010
|f5f9a1a6 a0404dea 36dcc949 9bcb25c9| .....@M.6..I..%. 00000020
|adc112b7 cc9a93ca e41f3262 cedfc1cc| ..........2b.... 00000030
|789afb17 6bf1fb71 a6756a5b 315bdbc2| x...k..q.uj[1[.. 00000040
|322f987f f3aa7b0c 7c2a6a7d         | 2/....{.|*j}     00000050
```

Hexdump of a minimal Streaming LZMA file using LZMA2 + no prefilter and single zero byte content:

```
|fedcba98 01010805 00000001 00000000| ................ 00000000
|00000000 01000000 00000000 05000000| ................ 00000010
|00000000 2d3adedf f11b61f1 4c886e35| ....-:....a.L.n5 00000020
|afa03673 6dcd87a7 4d27b5c1 510225d0| ..6sm...M'..Q.%. 00000030
|f592e213 c213b18e a038cbd9 669481d7| .........8..f... 00000040
|382c07d1 0c82c200 97993342 3a3340c2| 8,........3B:3@. 00000050
|48382018                           | H8 .             00000060
```

### A.2 Reed-Solomon Implementation

The reference implementation provides a stack only and efficient Reed-Solomon implementation in Rust.

## Appendix B: Reference Implementation

A reference implementation in Rust is available at https://github.com/hasenbanck/slz.

## Appendix C: Recommended File Extension

Files using this format SHOULD use the extension `.slz`.

## Revision History

- Version 1.0 (2025-08-11): Initial specification
