# TOA File Format Specification

Version 0.10

## 1. Introduction

### 1.1 Purpose

This document specifies the TOA, a compression and archive format for compressed data designed with four fundamental
capabilities at its core: streaming operation with parallel processing, corruption resilience through error correction,
efficient append operations, and deep integration with BLAKE3's cryptographic tree structure. The format uses LZMA2s,
a simplified version of LZMA2, which can be easily added to any LZMA based encoder / decoder, as the primary compression
algorithm.

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

### 1.4 Compression Approach: LZMA2s

TOA uses LZMA2s for compression, which is standard LZMA compression with a simplified framing layer. It's a simplified
version of LZMA2, without its complex state management. This approach deserves explicit clarification:

**LZMA2s is NOT a new compression algorithm.** It is standard LZMA compression with a simple chunking format. The actual
compression and decompression logic is identical to LZMA, which has been proven reliable over 20+ years of use.

The format adds only:

- A framing structure to divide data into chunks
- Control bytes to distinguish compressed from uncompressed chunks
- An improved encoding of using delta encoding for the chunk sizes
- Size limits that prevent worst-case expansion
- A simple state reset rule when switching chunk types

This design ensures:

- **Patent safety**: Uses only the well-established, patent-free LZMA algorithm
- **Implementation simplicity**: Any LZMA implementation can be adapted with ~100 lines of framing code
- **Proven reliability**: Leverages decades of LZMA field-testing
- **Catastrophic case handling**: Prevents expansion beyond original size through intelligent chunking

The technical details of the LZMA2s framing format are specified in Section 4.1.3.

### 1.5 Conventions

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
    - `0b01`: Standard - RS(255,239), 6.3% overhead, 8-byte correction capability
    - `0b10`: Paranoid - RS(255,223), 12.5% overhead, 16-byte correction capability
    - `0b11`: Extreme - RS(255,191), 25% overhead, 32-byte correction capability
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
- Primitive polynomial: x^8 + x^4 + x^3 + x + 1
- Generator: α = 3
- Code: RS(32,10)

## 4. Blocks Section

### 4.1 Block Structure

Each block MUST be self-contained with the following structure:

```
+---------------------+
| Block Header (64)   |  Size, hash, and RS parity
+---------------------+
| Compressed Data     |  LZMA2s stream (optionally RS-protected)
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

- LZMA2s encoder state MUST be reset for each block
- Prefilters (if used) MUST be reset for each block
- Each block MUST be decompressible in isolation
- Each block MUST be independently verifiable

#### 4.1.3 Compressed Data

The compressed data MUST be an LZMA2s stream. LZMA2s is a simplified variant of LZMA2 optimized for TOA's use case.

##### 4.1.3.1 LZMA2s Stream Format

An LZMA2s stream MUST consist of a sequence of chunks, each beginning with a control byte that determines the chunk type
and size. The stream MUST terminate with a control byte value of 0x00. Implementations MUST NOT process streams that
lack proper termination. Each chunk MUST be processed sequentially, and implementations MUST reject malformed chunk
sequences.

##### 4.1.3.2 Control Byte Encoding

The control byte MUST use the following encoding schemes. Implementations MUST reject control bytes that do not conform
to these patterns:

**End of Stream**: `0x00`

- MUST indicate the end of the LZMA2s stream
- MUST NOT be followed by any additional bytes
- Implementations MUST terminate processing upon encountering this byte

**Uncompressed Chunk**: `001sssss` + 2 bytes

- Bits 7-5: MUST be `001` to identify an uncompressed chunk
- Bits 4-0: MUST contain the high 5 bits of the 21-bit size
- The following 2 bytes MUST contain the middle and low bytes of size in big-endian order
- Implementations MUST calculate the actual size as encoded_size + 1
- The chunk data following these headers MUST be exactly the calculated size in bytes

**Compressed Chunk**: `010uuuuu` + 4 bytes

- Bits 7-5: MUST be `010` to identify a compressed chunk
- Bits 4-0: MUST contain the high 5 bits of the 21-bit uncompressed size
- The following 2 bytes MUST contain the middle and low bytes of uncompressed size
- The following 2 bytes MUST contain the 16-bit compressed size in big-endian order
- Implementations MUST calculate actual sizes as encoded_size + 1
- The compressed data MUST decompress to exactly the specified uncompressed size

**Delta Compressed Chunk**: `011uuuuu` + 3 bytes

- Bits 7-5: MUST be `011` to identify a delta compressed chunk
- Bits 4-0: MUST contain the high 5 bits of the 21-bit uncompressed size
- The following 2 bytes MUST contain the middle and low bytes of uncompressed size
- The following 1 byte MUST contain the delta from 65536
- Implementations MUST calculate compressed size as 65536 - delta
- The delta value MUST NOT exceed 65536

**Delta Uncompressed Chunk**: `1sdddddd` + 1 byte

- Bit 7: MUST be `1` to identify delta uncompressed chunk
- Bit 6: MUST be 0 to add to 65536, or 1 to subtract from 65536
- Bits 5-0: MUST contain the high 6 bits of the 14-bit delta
- The following 1 byte MUST contain the low 8 bits of delta
- Implementations MUST calculate size as 65536 ± delta
- The resulting size MUST be within the range 49,152 to 81,920 bytes inclusive

Decoders MUST reject any control byte patterns not defined above. Encoders MUST NOT generate undefined control byte
patterns.

You're absolutely right. Let me correct that section:

##### 4.1.3.3 State Management

LZMA2s implementations MUST maintain the following state constraints:

- Properties (lc, lp, pb) MUST remain constant throughout the entire stream
- Dictionary size MUST remain constant throughout the entire stream
- The LZMA decoder state MUST be reset when and only when transitioning from an uncompressed chunk to a compressed chunk
- The LZMA decoder state MUST NOT be reset at any other time
- Implementations MUST maintain dictionary contents across all chunks within the stream, regardless of chunk type
- The dictionary MUST only be reset at block boundaries, never within an LZMA2s stream

Encoders MUST ensure that chunk transitions respect these state management rules. Decoders MUST verify state consistency
and MUST reject streams that violate these constraints.

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

- Standard: MUST use 239 data bytes + 16 parity bytes (can correct 8 bytes per codeword)
- Paranoid: MUST use 223 data bytes + 32 parity bytes (can correct 16 bytes per codeword)
- Extreme: MUST use 191 data bytes + 64 parity bytes (can correct 32 bytes per codeword)

All protection levels MUST use the same field parameters as metadata protection:

- Field: GF(2^8)
- Primitive polynomial: x^8 + x^4 + x^3 + x + 1
- Generator: α = 3

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
- Primitive polynomial: x^8 + x^4 + x^3 + x + 1
- Code: RS(64,40)
- Generator: α = 3

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

### 10.2 LZMA2s over LZMA or LZMA2

**Criticism**: Why create a custom compression variant instead of using standard LZMA or LZMA2?

**Rationale**: LZMA2s was developed to address specific limitations discovered during empirical testing:

**Catastrophic Worst-Case Handling**: Pure LZMA can expand incompressible data beyond original size. While LZMA2 solves
this, it adds unnecessary complexity for TOA's use case.

**Lack of Formal Specification**: LZMA2 has no formal specification—it's defined by its reference implementation. Since
TOA requires a complete specification anyway, we can optimize the format.

**Simplified State Management**: LZMA2s only resets state when transitioning from uncompressed to compressed chunks.
LZMA2's complex state machine with property changes and dictionary resets is unnecessary when TOA already provides
block-level resets.

**Improved Efficiency**: Delta encoding for common chunk sizes (around 64KiB) saves 1 byte per chunk. For typical files
with many chunks, this provides measurable compression improvements.

**Minimal Implementation Changes**: LZMA2s only changes the control byte encoding—the underlying LZMA compression is
identical. This makes it easy to adapt existing LZMA and LZMA2 implementations.

The simplifications in LZMA2s align perfectly with TOA's design philosophy: maintaining simplicity while improving
efficiency, with changes minimal enough to be practical for upstream contribution.

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
fedcba980100003e5d10140ed92e0b7e
18866b3b1ad3127d3d32d6ce6dd6de3e
8000000000000000af1349b9f5f9a1a6
a0404dea36dcc9499bcb25c9adc112b7
cc9a93cae41f32625cf0fa99d34e6851
905c5dde0df7976421e6ba1fef77f31c
```

Hexdump of a single block file with a single compressed zero byte with the following configuration:

- Prefilter: BCJ X86
- LZMA LC: 3
- LZMA LP: 0
- LZMA PB: 2
- LZMA Dictionary size exponent: 30
- Block size exponent: 11

```
fedcba980100011f5d1e4821f8b455f1
dd66671d1cd18158eef29407d7902722
40000000000000052d3adedff11b61f1
4c886e35afa036736dcd87a74d27b5c1
510225d0f592e21319916b9a59885a7d
2ae4244c100b255e2451ff5682d77c10
200000000080000000000000012d3ade
dff11b61f14c886e35afa036736dcd87
a74d27b5c1510225d0f592e2138f3db9
e4bb5add135383b284084730db5626e6
2299458c1e
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

Parity:  00000000000000000000000000000000
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

Parity:  07ffcc5e9bfb1c0838aee03603b502aa
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

Parity:  93cca4cfe7c914d65c083eb57a634cd5a86f77ed
         f97b87cf4c05be2478e175d4
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

Parity:  792316db851127a71e19d44e5fe58400bffdc5be
         5a73b3b90f1b660ea25f08bfced98819758eabc2
         586966bee7b5abec7387eea89e0377f623340cf0
         6209b500
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

Parity:  579a5af18d3b67e5bfec98bb598dc2b4a5a7714d
         dc267cd9
```

Test 3:

```
Data:    000102030405060708090a0b0c0d0e0f10111213
         1415161718191a1b1c1d1e1f2021222324252627

Parity:  bb68ae9f872c2d5eb1c486a104d5d0d0e77140d3
         1e2ae52b
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

Parity:  6b947c9013410983bf927cd5eafba958214e0fee90ef
```

Test 3:

```
Data:    00010203040506070809

Parity:  2e15b80a2d182f2a0e46a888cf8803394a8b5cdba41d
```

## Appendix B: Reference Implementation

A reference implementation in Rust is available at https://github.com/hasenbanck/toa.

Implementations MAY consult this reference for clarification of requirements.

## Appendix C: Recommended File Extension

Files using this format SHOULD use the extension `.toa`.

## Revision History

- Version 0.10 (2025-08-27): Change wording of the LZMA2s normative section
- Version 0.9  (2025-08-22): Changes in the ECC:
    - Switched polynomial for Reed-Solomon ECC from 0x11D (x^8 + x^4 + x^3 + x^2 + 1) to
      0x11B (x^8 + x^4 + x^3 + x + 1) for better CPU instruction set support (like x86's GFNI)
- Version 0.8  (2025-08-22): Spitched from LZMA to LZMA2s for better worst case performance.
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
