# TOA File Format Specification

Version 0.7

## 1. Introduction

### 1.1 Purpose

This document specifies the TOA, a compression and archive format for compressed data designed with four fundamental
capabilities at its core: streaming operation with parallel processing, corruption resilience through error correction,
efficient append operations, and deep integration with BLAKE3's cryptographic tree structure. The format uses LZMA as
the primary compression algorithm.

### 1.2 Core Design Principles

TOA is built around several interconnected design principles that work together to provide unique capabilities:

**Streaming-Optimized Architecture**: The format is highly optimized for streaming decompression - readers can process
data purely sequentially as it arrives without any seeking. Writers can operate in streaming mode with a single
block-sized buffer, or use seeking for zero-copy operation. The MSB-based block/trailer distinction allows parsers
to identify structure types from just the first 1 byte, without special markers or lookahead.

**Parallel Processing While Streaming**: TOA divides input into independent blocks that can be compressed and
decompressed concurrently. Each block includes its BLAKE3 chaining value, enabling parallel hash computation. This
parallelism is achieved without sacrificing the streaming property - block boundaries are discoverable on-the-fly
through size fields in block headers.

**Built-in Corruption Resilience**: The format employs Reed-Solomon error correction codes at multiple levels:

- File header: RS(32,10) can correct up to 11 bytes of corruption in the 32-byte header
- Block headers: RS(64,40) can correct up to 12 bytes of corruption per 64-byte block header
- Final trailer: RS(64,40) can correct up to 12 bytes of corruption per 64-byte file trailer
- Data (optional): Configurable RS protection for compressed data with three levels of redundancy

This multi-layered protection enables recovery from significant corruption that would be fatal in unprotected formats.
Each block can be validated independently, enabling partial file recovery and pinpointing corruption locations.

**Native BLAKE3 Integration**: The format deeply integrates with BLAKE3's tree structure rather than treating hashing as
an afterthought. Each block stores a chaining value that forms part of BLAKE3's binary tree. This enables:

- Parallel hash computation that scales with available cores
- Incremental verification as data streams
- Verified streaming and selective decompression use cases
- Efficient append operations (O(n) in block count, not data size)

**Simplicity Through Consistency**: Despite its advanced features, the format maintains simplicity through consistent
design choices:

- Fixed-size metadata structures where practical
- Big-endian encoding throughout
- Power-of-2 block sizes that align with BLAKE3's tree structure
- Uniform Reed-Solomon protection using the same field parameters

### 1.3 Key Capabilities

The combination of these design principles enables several unique capabilities:

**Progressive Validation**: Data integrity can be verified as it streams, without waiting for the complete file.
Applications can detect corruption early and take action (request retransmission, mark blocks as damaged, etc.) without
processing the entire archive.

**Granular Error Recovery**: When corruption occurs, the format can identify exactly which blocks are affected.
Even with uncorrectable corruption in some blocks, other blocks remain recoverable.

**Efficient Incremental Operations**:

- **Appending**: When the last block is full, new data can be appended by updating only the chain of blocks and
  trailer - existing, full blocks never need recompression. If the last block is not full it needs recompression though.
- **Modification**: Changes to any block require recomputing only that block and the re-calculation of the root hash
  through the chain of blake3's chaining values.
- **Verification**: Individual blocks or ranges can be verified without processing the entire file.

**Scalable Performance**: The format scales naturally with available hardware:

- Single-threaded: Efficient sequential processing
- Multi-core: Recursive divide-and-conquer parallelization
- Zero-buffer streaming: Decompression requires no buffering

### 1.4 Conventions

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "
OPTIONAL" in this document are to be interpreted as described in RFC 2119.

Byte values are shown in hexadecimal notation (e.g., 0xFE). Multibyte sequences are shown with the first byte leftmost.
All multibyte integers use big-endian encoding.

### 1.5 Terminology

**Physical vs Uncompressed Size**: The *physical block size* is the actual size of the block data. The
*uncompressed size* is the original data size before compression and adding optional error correction.

**Full vs Partial Blocks**: *Full blocks* MUST have uncompressed size exactly equal to the configured block size. Only
the final block MAY be *partial* (smaller than block size).

**Chunk vs Block**: In BLAKE3 terminology, a *chunk* is up to 1024 bytes of input data. In TOA, *block*
refers to the compression unit (configured via block_size, minimum 64 KiB). Each TOA block MUST contain many
BLAKE3 chunks.

**Chaining Value (CV)**: A 32-byte BLAKE3 intermediate value representing a node in the hash tree. Each block MUST
produce a CV that becomes part of the tree structure.

**Root Hash**: The final 32-byte BLAKE3 hash computed by merging all chaining values according to the tree structure.

**Reed-Solomon Protection Levels**:

- **Metadata protection**: REQUIRED - protects headers and trailers
- **Data protection**: OPTIONAL - three configurable levels for compressed data

## 2. File Structure

A TOA file MUST consist of exactly three sections:

```
+==================+
|      Header      |  Fixed 32 bytes, RS-protected configuration
+==================+
|                  |
|      Blocks      |  Variable number of independently compressed blocks.
|                  |  MAY contain no blocks.
+==================+
|   Final Trailer  |  Fixed 64 bytes, RS-protected integrity data
+==================+
```

Every section is processable without knowledge of what follows, enabling true streaming operation.

## 3. Header Format

The header MUST contain format identification and compression configuration, protected by Reed-Solomon codes:

```
+------+------+------+-------+
| 0xFE | 0xDC | 0xBA | 0x98  |  Magic bytes (4 bytes)
+------+------+------+-------+
|  Version |  Capabilities   |  Version and capabilities (2 bytes)
+------+------+------+-------+
| Prefilter | Block Size Exp |  Prefilter and block size (2 bytes)
+------+------+------+-------+
|      LZMA Properties       |  (2 bytes)
+----------------------------+
|    Reed-Solomon Parity     |  (22 bytes)
+----------------------------+
```

### 3.1 Magic Bytes

Files MUST begin with the four-byte sequence 0xFE 0xDC 0xBA 0x98. This sequence is not valid UTF-8 and contains no
printable ASCII characters.

Decoders MUST verify these bytes before processing. Decoders MUST reject files that do not begin with this sequence.

### 3.2 Version

The version field MUST be one byte indicating the format version. This specification defines version 0x01.

Decoders MUST reject files with unsupported version numbers.

### 3.3 Capabilities

One byte indicating optional features and protection levels:

- **Bits 0-1**: Data protection level
    - `0b00`: None (metadata only)
    - `0b01`: Light - RS(255,239), 6.3% overhead, 8-byte correction capability
    - `0b10`: Medium - RS(255,223), 12.5% overhead, 16-byte correction capability
    - `0b11`: Heavy - RS(255,191), 25% overhead, 32-byte correction capability
- **Bits 2-7**: MUST be zero (reserved for future use)

When data protection is enabled (bits 0-1 ≠ 0b00), compressed block data MUST be encoded with Reed-Solomon protection as
specified in Section 4.3.

### 3.4 Prefilter Selection

One byte indicating the optional prefilter. Valid values:

- 0x00: No prefilter
- 0x01: BCJ x86
- 0x02: BCJ ARM
- 0x03: BCJ ARM Thumb
- 0x04: BCJ ARM64
- 0x05: BCJ SPARC
- 0x06: BCJ PowerPC
- 0x07: BCJ IA64
- 0x08: BCJ RISC-V
- 0x09-0xFF: Reserved (MUST NOT be used)

Prefilters MUST be reset at block boundaries to maintain block independence.

### 3.5 Block Size

One byte encoding the block size as a power of 2. The block size MUST be 2^n bytes where:

- n MUST be in the range [16, 62]
- Minimum: n=16 → 2^16 = 64 KiB
- Maximum: n=62 → 2^62 = 4 EiB

The block size MUST be a power of 2 to maintain BLAKE3's tree structure alignment.

Examples:

- n=16: 2^16 = 64 KiB
- n=24: 2^24 = 16 MiB
- n=31: 2^31 = 2 GiB
- n=62: 2^62 = 4 EiB

**Important**: The block size determines the uncompressed size of all full blocks. Only the last block MAY be partial
(smaller than block size).

### 3.6 LZMA Properties

Two bytes encoding LZMA compression parameters:

- **Byte 0**: Properties byte MUST encode (pb * 5 + lp) * 9 + lc where:
    - lc: number of literal context bits (MUST be 0-8)
    - lp: number of literal position bits (MUST be 0-4)
    - pb: number of position bits (MUST be 0-4)
- **Byte 1**: Dictionary size as 2^n bytes where n MUST be in range [16, 31]

Valid dictionary sizes range from 64 KiB (n=16) to 2 GiB (n=31).

### 3.7 Reed-Solomon Protection

The header MUST be protected by 24 bytes of Reed-Solomon parity using RS(32,10) code.

Parameters that MUST be used:

- Field: GF(2^8)
- Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
- Generator: α = 2
- Code: RS(32,10)

## 4. Blocks Section

### 4.1 Block Structure

Each block MUST be self-contained with the following structure:

```
+---------------------+
| Block Header (64)   |  Size, hash, and RS parity
+---------------------+
| Compressed Data     |  LZMA stream (optionally RS-protected)
+---------------------+
```

#### 4.1.1 Block Header Format

Each block header MUST contain:

```
+-------------------------+
| Physical Block Size (8) |  Size with type flags in MSBs
+-------------------------+
| BLAKE3 Chaining Value   |  32-byte tree node value
+-------------------------+
| RS Parity (24)          |  Reed-Solomon protection
+-------------------------+
```

**Size Field Requirements**: The size field MUST use the following bit allocation:

- Bit 0 (MSB): MUST be 0 for block headers, 1 for final trailer
- Bit 1: For blocks, MUST be 0 for full blocks, 1 for partial blocks
- Bits 2-63: Physical block size in bytes (excluding header)

Parsers MUST identify structure type from the first byte's MSB. Implementations MUST NOT use special markers for
structure identification.

#### 4.1.2 Block Independence

Each block MUST be completely independent:

- LZMA encoder state MUST be reset for each block
- Prefilters (if used) MUST be reset for each block
- Each block MUST be decompressible in isolation
- Each block MUST be independently verifiable

#### 4.1.3 Compressed Data

The compressed data MUST be a raw LZMA stream with end-of-stream marker (the distance-length pair MUST be 0xFFFFFFFF,
2).

### 4.2 BLAKE3 Tree Integration

The chaining value in each block header MUST be a node in BLAKE3's binary tree structure. Implementations MUST:

- Compute chaining values with correct input offsets
- Maintain proper tree structure for all operations
- Use power-of-2 block sizes to ensure alignment

### 4.3 Reed-Solomon Data Protection

When data protection is enabled (capabilities bits 0-1 ≠ 0b00), compressed data MUST be encoded in Reed-Solomon
codewords:

```
For each codeword:
+----------------------+
| Data (239/223/191 B) |  Compressed LZMA data
| Parity (16/32/64 B)  |  RS correction codes
+----------------------+
```

The protection level determines the codeword structure:

- Light: MUST use 239 data bytes + 16 parity bytes (can correct 8 bytes per codeword)
- Medium: MUST use 223 data bytes + 32 parity bytes (can correct 16 bytes per codeword)
- Heavy: MUST use 191 data bytes + 64 parity bytes (can correct 32 bytes per codeword)

All protection levels MUST use the same field parameters as metadata protection:

- Field: GF(2^8)
- Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
- Generator: α = 2

The LZMA end-of-stream marker MUST be preserved to ensure proper termination even with padding.

## 5. Final Trailer Format

The trailer MUST provide whole-file integrity with the following structure:

```
+---------------------+
| Total Uncompressed  |  8 bytes, MSB = 1 for identification
+---------------------+
| BLAKE3 Root Hash    |  32 bytes, computed from tree structure
+---------------------+
| Reed-Solomon Parity |  24 bytes, RS(64,40) protection
+---------------------+
```

### 5.1 Total Uncompressed Size with Trailer Flag

The size field MUST use the following bit allocation:

- Bit 0 (MSB): MUST be 1 to indicate final trailer
- Bits 1-63: Total size of all decompressed data in bytes

The maximum representable uncompressed size SHALL be 2^63 - 1 bytes.

### 5.2 BLAKE3 Root Hash

The root hash MUST be the 256-bit BLAKE3 hash computed by properly merging all block chaining values according to the
BLAKE3 tree structure.

### 5.3 Reed-Solomon Error Correction

The trailer MUST include 24 bytes of Reed-Solomon parity protecting both the total uncompressed size and BLAKE3 root
hash.

Parameters that MUST be used:

- Field: GF(2^8)
- Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
- Code: RS(64,40)
- Generator: α = 2

The 8-byte size and 32-byte hash MUST be treated as 40 consecutive bytes for Reed-Solomon encoding. Implementations MUST
NOT reorder bytes or perform integer interpretation.

Decoders MUST support correction of up to 12 byte errors using traditional unique decoding algorithms. Implementations
MAY employ list decoding algorithms to attempt recovery beyond 12 errors, using the BLAKE3 hash for disambiguation. When
list decoding succeeds beyond the traditional bound, implementations SHOULD indicate reduced confidence to the user.

## 6. Streaming Processing

### 6.1 Streaming Compression

Implementations that support streaming compression MUST:

1. Implementations MUST write RS-protected header
2. For each block of input, implementations MUST:
    - Compress up to block_size bytes of data with LZMA
    - Compute BLAKE3 chaining value incrementally
    - Determine if more data follows (affects CV finalization)
    - Set physical block size field with appropriate flags
    - Write RS-protected block header with known compressed size
    - Write compressed data
3. Implementations MUST merge chaining values for BLAKE3's root hash
4. Implementations MUST write RS-protected trailer

Implementations MAY use zero-copy compression with seeking by:

- Compressing from input and writing directly
- Seeking back to write compressed size in block header

### 6.2 Streaming Decompression

Implementations that support streaming decompression MUST:

1. Read and verify header (MUST apply RS correction if needed)
2. For each 64-byte structure:
    - MUST check MSB to identify block header vs trailer
    - If block: MUST read exact size from header, decompress, verify and collect CV
    - If trailer: MUST verify root hash using all collected CVs
3. MUST report any corruption detected and corrected

### 6.3 Parallel Streaming

Implementations MAY achieve parallelism while streaming by:

- Discovering block boundaries via size fields
- Distributing blocks to worker threads
- Verifying blocks independently
- Merging chaining values in tree order

### 6.4 Incremental Verification

Implementations MUST support three levels of verification:

1. **Block-level**: Each block's chaining value MUST be verifiable independently with RS correction
2. **Progressive**: Blocks SHOULD be verifiable as they stream without waiting for completion
3. **Full**: Final root hash MUST verify complete integrity

## 7. Corruption Resilience

### 7.1 Multi-Layer Protection

Implementations MUST provide six layers of integrity protection:

1. Header RS codes MUST protect configuration
2. LZMA stream MUST provide built-in consistency checks
3. Each block MUST have cryptographic verification via chaining value
4. Block header RS codes MUST protect metadata per block
5. Tree structure MUST be validated for correct CV relationships
6. Root hash with RS MUST provide final file-level verification

### 7.2 Progressive Error Detection

Implementations SHOULD detect and localize corruption as data streams:

- Early detection without processing entire file
- Precise localization to specific blocks
- Partial recovery of valid blocks
- RS correction where possible

### 7.3 Recovery Scenarios

Implementations MUST handle the following failure modes:

- **Bit flips**: MUST be corrected by RS codes within limits
- **Burst errors**: MUST be corrected up to RS limits per codeword
- **Missing blocks**: MUST be detected via tree structure
- **Truncation**: MUST be detected via trailer absence
- **Systematic corruption**: MUST be pinpointed to specific blocks

## 8. Efficient Append Operations

### 8.1 Append Algorithm

When the last block is full, implementations MAY support efficient appending:

1. Read existing block headers (not data)
2. Collect chaining values
3. Seek to trailer position
4. Overwrite trailer with new blocks
5. Update trailer with new root hash

Complexity MUST be O(n) in block count, not data size.

If the last block is partial, implementations MUST recompress it with appended data.

### 8.2 Tree Structure Preservation

To maintain BLAKE3 tree structure, implementations MUST:

- Use power-of-2 block sizes
- Ensure all blocks except possibly the last are full
- Track CV offsets properly

This ensures append operations produce identical results to compression from scratch.

## 9. Security Considerations

### 9.1 Cryptographic Properties

Implementations MUST understand the following properties:

- **BLAKE3**: Provides 128-bit collision resistance and 256-bit preimage resistance
- **Tree structure**: Prevents length extension attacks
- **Domain separation**: Flags prevent cross-domain attacks
- **RS protection**: Prevents hash manipulation

### 9.2 Implementation Safety

Implementations MUST:

- Validate size fields before allocation
- Prevent integer overflow in offset calculations
- Validate block sizes are power-of-2
- Verify MSB flags for structure identification

Implementations MUST NOT:

- Allocate memory based on unvalidated size fields
- Allow integer overflow in calculations
- Accept non-power-of-2 block sizes
- Process data without verifying structure type

## 10. Design Decisions

### 10.1 BLAKE3 over CRC32

**Criticism**: CRC32 is sufficient for error detection in compressed formats. Cryptographic hashes add unnecessary
complexity and computational overhead without meaningful benefit for integrity checking.

**Rationale**: BLAKE3 was chosen not for a single purpose but as a multipurpose tool that justifies its inclusion:

**Performance Superiority**: Modern BLAKE3 implementations with SIMD support achieve ~7 GiB/s on current hardware,
actually *exceeding* CRC32 performance (~3-4 GiB/s) while providing cryptographic security. This counterintuitive result
stems from BLAKE3's design for parallel processing and its efficient use of modern CPU instructions.

**Multiple Use Cases**:

- **Content addressing**: The hash serves as a globally unique identifier for deduplication systems
- **Out-of-band verification**: Users can transmit the hash separately for independent validation
- **Audit trails**: Provides cryptographic proof of file contents for compliance and legal requirements
- **Tamper detection**: Detects intentional manipulation, not just accidental corruption

**Tree Structure Benefits**: BLAKE3's native tree mode perfectly aligns with our block-based design, enabling:

- Parallel hash computation that scales linearly with available cores
- Incremental verification as data streams
- Efficient append operations through chaining value reuse
- Verified streaming and selective decompression use cases

The choice of BLAKE3 transforms the format from a simple compression container into a cryptographically secure,
parallelizable system suitable for modern distributed and untrusted environments.

### 10.2 LZMA over LZMA2

**Criticism**: Why use LZMA instead of its successor LZMA2, which adds features like uncompressed chunks and better
streaming support?

**Rationale**: Empirical testing across diverse datasets revealed that LZMA consistently outperforms LZMA2 in our
format:

**Compression Efficiency**: Across test data including Linux kernel sources, executables, and multimedia files, LZMA
produced consistently smaller output than LZMA2. The overhead from LZMA2's chunk headers and control bytes negates its
theoretical advantages in our already-chunked design.

**Redundant Feature**: LZMA2's other advantage - the memory-bounded operation - is already provided by our block
structure. Each TOA block is independently compressed with reset state, achieving the same benefits without
LZMA2's overhead.

**Simplicity**: LZMA's simpler structure reduces implementation complexity. The end-of-stream marker (0xFFFFFFFF, 2)
provides clean termination even with Reed-Solomon padding, while LZMA2's multi-chunk structure would complicate our RS
codeword alignment.

### 10.3 Big-Endian over Little-Endian

**Criticism**: Little-endian is more natural for modern processors and is used by most contemporary formats.

**Rationale**: Big-endian byte order was chosen for superior streaming characteristics:

**MSB-First Identification**: The most significant bit flags in our size fields (distinguishing blocks from trailers)
can be identified from the very first byte. With big-endian encoding, a streaming parser immediately knows the structure
type without buffering 8 bytes. This enables:

- Zero-lookahead parsing
- Immediate branching decisions in streaming decoders

**Network Protocol Alignment**: Big-endian (network byte order) is standard in network protocols. This alignment
simplifies implementation in network-oriented applications and reduces confusion when the format is used in distributed
systems.

**Consistent Parsing**: While modern CPUs handle both byte orders efficiently through dedicated instructions
(bswap/rev), the parsing advantage of immediate MSB access outweighs any theoretical CPU preference, especially since
byte order conversion happens once per 64-byte header, not per data byte.

### 10.4 Reed-Solomon Error Correction

**Criticism**: Reed-Solomon codes add complexity and overhead. Most corruption in practice is detected by checksums, and
users simply re-download corrupted files.

**Rationale**: Reed-Solomon codes transform the format from fragile to resilient:

**Proven Reliability**: RS codes have been successfully deployed for decades in CD/DVD media, QR codes, satellite
communications, and RAID systems. The mathematics are thoroughly understood, and battle-tested implementations exist in
the public domain.

**Real-World Corruption Patterns**: RS codes excel at handling the burst errors common in real storage media:

- Tape storage: Sequential read errors from media defects
- Optical media: Scratches and degradation
- Network transmission: Packet loss and corruption
- Long-term storage: Bit rot and sector failures

**Multi-Layer Protection**:

- **Metadata**: Always protected, ensuring structure remains parseable
- **Data**: Optional protection with three levels of redundancy
- **Progressive Recovery**: Can identify and potentially recover individual corrupted blocks

**Overhead Justification**: The 24-byte RS overhead per 64-byte header (37.5%) provides the ability to correct up to 12
bytes of corruption—enough to recover from severe damage that would render other formats completely unusable. For a
typical file with 1 MiB blocks, this overhead amounts to less than 0.01% of total size while providing high resilience.

The combination of BLAKE3 for detection and Reed-Solomon for correction creates a unique "detect-and-repair" capability
absent from other compression formats, enabling use cases in unreliable or degraded storage environments where simple
retry isn't an option.

## 11. Acknowledgements

The TOA format builds upon decades of compression research and development. We acknowledge:

- **Igor Pavlov** for creating the LZMA algorithm
- **Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko** for developing BLAKE3 and specifically designing
  its tree mode for parallel processing
- **Irving S. Reed and Gustave Solomon** for their pioneering work on error correction codes
- **The XZ Utils project** (Lasse Collin and contributors) for advancing LZMA-based compression
- **The lzip project** (Antonio Diaz Diaz) for demonstrating the value of simplicity
- **The Bao project** for showing practical applications of BLAKE3's tree structure
- The broader compression community for continuous innovation in data compression techniques

## 12. Intellectual Property Notice

### 12.1 Specification License

This specification is placed in the **public domain**. Anyone MAY freely implement, use, modify, or distribute this
specification without restriction.

### 12.2 Patent Disclaimer

To the best of the authors' knowledge, the TOA format as specified in this document is not encumbered by
patents. The core technologies are believed to be patent-free.

- LZMA algorithm is believed to be patent-free and has been widely implemented without patent claims for over 20 years
- Blake3 is explicitly released under CC0 (public domain) with no known patent encumbrances
- Reed-Solomon codes have been in public use since 1960 with expired foundational patents
- BCJ filters are well-established techniques without known patent claims

**This document does not constitute legal advice**. Implementers are responsible for their own patent review and risk
assessment. The authors make no warranties regarding patent status and assume no liability for implementations based
on this specification.

### 12.3 Trademark Notice

"TOA" is not a registered trademark. The name MAY be used freely to identify implementations of this
specification.

## Appendix A: Test Vectors

### A.1 Minimal File

Hexdump of an empty file with the following configuration:

- Prefilter: None
- LZMA LC: 3
- LZMA LP: 0
- LZMA PB: 2
- LZMA Dictionary size exponent: 16
- Block size exponent: 62

```
fedcba980100003e5d10a41b4946bc0d
b0d277d8f82b4b630fbc97d7615530a9
8000000000000000af1349b9f5f9a1a6
a0404dea36dcc9499bcb25c9adc112b7
cc9a93cae41f3262a2b54a54b5f88a30
271d41dceb661a679fbd77edc3f9040a
```

Hexdump of a single block file with a single compressed zero byte with the following configuration:

- Prefilter: BCJ X86
- LZMA LC: 3
- LZMA LP: 0
- LZMA PB: 2
- LZMA Dictionary size exponent: 30
- Block size exponent: 11

```
fedcba980100011f5d1e884b0ed50069
d44c9ae6faa030510e67da670b3259a2
400000000000000b2d3adedff11b61f1
4c886e35afa036736dcd87a74d27b5c1
510225d0f592e21320fe0ef111f7500f
a4207a02281c71866fb1ec323892b227
000041fef7ffffe00080008000000000
0000012d3adedff11b61f14c886e35af
a036736dcd87a74d27b5c1510225d0f5
92e2137e40e16f84c3e6a17e3c65da1f
2c61ddd66d5f4a662c32b9
```

### A.2 Block Chaining Example

For a 3-block file with block size 2^16 (64 KiB), the chaining value computation:

```
# Block 0: offset=0, size=65536 (full block)
cv_0 = BLAKE3(data_0, offset=0, non_root)

# Block 1: offset=65536, size=65536 (full block)
cv_1 = BLAKE3(data_1, offset=65536, non_root)

# Block 2: offset=131072, size=512 (partial block)
cv_2 = BLAKE3(data_2, offset=131072, non_root)

root = merge_tree(cv_0, cv_1, cv_2, root=true)
```

### A.3 Reed-Solomon Implementation

The reference implementation provides a stack-only and efficient Reed-Solomon
implementation written in Rust, which code is in the public domain.

#### A.3.1 - Test vectors for RS(255,239)

Test 1:

```
Data:    0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         00000000000000000000000000000000000000

Parity:  0000000000000000000000000000000000000000
         00000000
```

Test 2:

```
Data:    ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffff

Parity:  ffffffffffffffffffffffffffffffff
```

Test 3:

```
Data:    000102030405060708090a0b0c0d0e0f10111213
         1415161718191a1b1c1d1e1f2021222324252627
         28292a2b2c2d2e2f303132333435363738393a3b
         3c3d3e3f404142434445464748494a4b4c4d4e4f
         505152535455565758595a5b5c5d5e5f60616263
         6465666768696a6b6c6d6e6f7071727374757677
         78797a7b7c7d7e7f808182838485868788898a8b
         8c8d8e8f909192939495969798999a9b9c9d9e9f
         a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3
         b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7
         c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadb
         dcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedee

Parity:  b173d9afcc56f1636e325dc22984f527
```

#### A.3.2 - Test vectors for RS(255,223)

Test 1:

```
Data:    0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         000000

Parity:  0000000000000000000000000000000000000000
         000000000000000000000000
```

Test 2:

```
Data:    ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffff

Parity:  ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffff
```

Test 3:

```
Data:    000102030405060708090a0b0c0d0e0f10111213
         1415161718191a1b1c1d1e1f2021222324252627
         28292a2b2c2d2e2f303132333435363738393a3b
         3c3d3e3f404142434445464748494a4b4c4d4e4f
         505152535455565758595a5b5c5d5e5f60616263
         6465666768696a6b6c6d6e6f7071727374757677
         78797a7b7c7d7e7f808182838485868788898a8b
         8c8d8e8f909192939495969798999a9b9c9d9e9f
         a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3
         b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7
         c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadb
         dcddde

Parity:  9c04c041d1ce5905b434daf6e5465f92d14ef9c2
         e2016cc2bbf0773a018bc2aa
```

#### A.3.3 - Test vectors for RS(255,191)

Test 1:

```
Data:    0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000

Parity:  0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000
         00000000
```

Test 2:

```
Data:    ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffff

Parity:  ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff
         ffffffff
```

Test 3:

```
Data:    000102030405060708090a0b0c0d0e0f10111213
         1415161718191a1b1c1d1e1f2021222324252627
         28292a2b2c2d2e2f303132333435363738393a3b
         3c3d3e3f404142434445464748494a4b4c4d4e4f
         505152535455565758595a5b5c5d5e5f60616263
         6465666768696a6b6c6d6e6f7071727374757677
         78797a7b7c7d7e7f808182838485868788898a8b
         8c8d8e8f909192939495969798999a9b9c9d9e9f
         a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3
         b4b5b6b7b8b9babbbcbdbe

Parity:  e8036c9c7298995a41a264a425fd1c9fe71e45f8
         4f2dbbec9240caa1bbc44ae55529991460cb8bc3
         2fbbb9e129bc6017f896f6a0a60677c657e04a54
         dfb7c62a
```

#### A.3.4 - Test vectors for RS(64,40)

Test 1:

```
Data:    0000000000000000000000000000000000000000
         0000000000000000000000000000000000000000

Parity:  0000000000000000000000000000000000000000
         00000000
```

Test 2:

```
Data:    ffffffffffffffffffffffffffffffffffffffff
         ffffffffffffffffffffffffffffffffffffffff

Parity:  e81d42b0548bfb1c5e9d0475a75446c6bda44e0b
         8ea6e459
```

Test 3:

```
Data:    000102030405060708090a0b0c0d0e0f10111213
         1415161718191a1b1c1d1e1f2021222324252627

Parity:  9fb10923191a0659292e6e7c5ee8fbf0111329eb
         8bdaefe8
```

#### A.3.5 - Test vectors for RS(32,10)

Test 1:

```
Data:    00000000000000000000

Parity:  00000000000000000000000000000000000000000000
```

Test 2:

```
Data:    ffffffffffffffffffff

Parity:  ad52e479625d811b5e60e40fafd4eb5b68eeb3847978
```

Test 3:

```
Data:    00010203040506070809

Parity:  fe98b737bc91e51a91a17ced02342c9688e2688eb3fd
```

## Appendix B: Reference Implementation

A reference implementation in Rust is available at https://github.com/hasenbanck/toa.

Implementations MAY consult this reference for clarification of requirements.

## Appendix C: Recommended File Extension

Files using this format SHOULD use the extension `.toa`.

## Revision History

- Version 0.7 (2025-08-21): Update name and some refinements:
    - Changed integer layout from little-endian to big-endian.
    - Changed header size from 34 to 32 bytes to be aligned to 8 bytes.
- Version 0.6 (2025-08-20): Added data protection using RS.
- Version 0.5 (2025-08-18): Major revision for improved robustness
    - Moved block trailer to header with RS(64,40) protection
    - Added RS(34,10) protection to file header
    - Removed Delta prefilter and end-of-blocks marker
    - Added capabilities field for future extensibility
    - Use MSB flags to distinguish block headers from final trailer
    - Renamed compressed block size to physical block size
- Version 0.4 (2025-08-17): Added block trailers with chaining values and Reed-Solomon protection
- Version 0.3 (2025-08-15): Initial specification
