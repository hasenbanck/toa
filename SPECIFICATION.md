# Streaming-LZMA Archive Format Specification

Version 0.5

## 1. Introduction

### 1.1 Purpose

This document specifies the Streaming-LZMA archive format, a container format for LZMA-compressed data designed for
streaming operation, parallel processing, robust data integrity verification, and efficient append operations.

### 1.2 Theory of Operation

The Streaming-LZMA format addresses practical requirements in modern data archival and transmission:

**Streaming Operation**: The format can be written and read sequentially without seeking, enabling use in pipelines,
network streams, and tape storage systems. Writers do not need to know the total data size or block count before
beginning compression.

**Parallel Processing**: Data is organized in independent blocks that can be compressed and decompressed concurrently.
Each block includes its BLAKE3 chaining value, enabling parallel hash computation during both compression and
decompression. Block boundaries are discoverable without parsing the entire file.

**Incremental Verification**: Each block contains its own integrity information protected by Reed-Solomon codes,
enabling per-block validation and partial file verification without processing the entire archive.

**Efficient Append Operations**: The inclusion of BLAKE3 chaining values per block enables efficient append operations.
When the last block is full (equals the configured block size), appending is O(n) where n is the number of blocks.
When the last block is partial, it must be recompressed with the appended data to maintain the BLAKE3 tree structure.

**Data Integrity**: Multiple validation layers protect against corruption. The format employs Blake3 hashing for
content verification at both block and file levels, with Reed-Solomon error correction codes protecting each hash
against corruption. This multi-layered approach guards against both random and systematic errors.

**Simplicity**: The format uses fixed-size fields where practical and avoids unnecessary complexity. All multibyte
integers use little-endian encoding. Only LZMA compression is supported.

### 1.3 Conventions

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC 2119.

Byte values are shown in hexadecimal notation (e.g., 0xFE). Multibyte sequences are shown with the first byte leftmost.

## 2. File Structure

A Streaming-LZMA file consists of three sections:

```
+==================+
|      Header      |  (Fixed: 34 bytes)
+==================+
|      Blocks      |  (Variable: 0 or more blocks with headers)
+==================+
|   Final Trailer  |  (Fixed: 64 bytes)
+==================+
```

## 3. Header Format

The header contains format identification and compression configuration, protected by Reed-Solomon codes:

```
+------+------+------+-------+
| 0xFE | 0xDC | 0xBA | 0x98  |  Magic bytes (4 bytes)
+------+------+------+-------+
|  Version |  Capabilities   |  Version and capabilities (2 bytes)
+------+------+------+-------+
| Prefilter | Block Size Exp |  Prefilter and block size (2 bytes)
+------+------+------+-------+
|   LZMA Properties          |  (2 bytes)
+----------------------------+
|   Reed-Solomon Parity      |  (24 bytes)
+----------------------------+
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

### 3.3 Capabilities

One byte reserved for future capabilities. Currently set to 0x00.

Future versions may use this field to indicate optional features such as different error correction levels
for compressed data.

### 3.4 Prefilter Selection

One byte indicating the optional prefilter:

- 0x00: No prefilter
- 0x01: BCJ x86
- 0x02: BCJ ARM
- 0x03: BCJ ARM Thumb
- 0x04: BCJ ARM64
- 0x05: BCJ SPARC
- 0x06: BCJ PowerPC
- 0x07: BCJ IA64
- 0x08: BCJ RISC-V
- 0x09-0xFF: Reserved

The BCJ filters are the same as used by LZMA SDK and liblzma. No additional properties are needed
as the offset is always 0.

### 3.5 Block Size

One byte encoding the block size as a power of 2:

- Block size = 2^n bytes where n is the value of this byte
- Valid range: n ∈ [16, 62] (64 KiB to 4 EiB)
- Minimum: n=16 → 2^16 = 64 KiB
- Maximum: n=62 → 2^62 = 4 EiB

Examples:

- n=16: 2^16 = 64 KiB
- n=24: 2^24 = 16 MiB
- n=31: 2^31 = 2 GiB
- n=62: 2^62 = 4 EiB

**Important**: The block size determines the uncompressed size of all full blocks.
Only the last block may be partial (smaller than block size).

### 3.6 LZMA Properties

Two bytes encoding LZMA compression parameters:

- **Byte 0**: Properties byte encoding (pb * 5 + lp) * 9 + lc
    - lc: number of literal context bits (0-8)
    - lp: number of literal position bits (0-4)
    - pb: number of position bits (0-4)
- **Byte 1**: Dictionary size as 2^n bytes where n is the value of this byte

Valid dictionary sizes range from 64 KiB (n=16) to 2 GiB (n=31).

Examples:

- n=16: 2^16 = 64 KiB
- n=24: 2^24 = 16 MiB
- n=31: 2^31 = 2 GiB

**Note on LZMA parameters**: While the default LZMA parameters (lc=3, lp=0, pb=2) work
well for most data, BCJ filters benefit from adjusted parameters. For example:

- ARM64 executable: lc=2,lp=2,pb=2
- RISC-V executable: lc=2,lp=2,pb=2
- RISC-V executable with compressed instructions: lc=3,lp=1,pb=2
- x86 executables: lc=3,lp=0,pb=2 (default)

### 3.7 Reed-Solomon Protection

The header is protected by 24 bytes of Reed-Solomon parity using a shortened RS(34,10) code.
This is derived from the same RS(64,40) code used for blocks but shortened to accommodate
the 10-byte header payload.

Parameters:

- Field: GF(2^8)
- Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
- Code: Shortened RS(34,10) from RS(64,40)
- Generator: α = 2

## 4. Blocks Section

The blocks section contains compressed blocks, each with its own header.

```
+========================+
| Block 0                |
|  +------------------+  |
|  | Block Header     |  |
|  | Compressed Data  |  |
|  +------------------+  |
+========================+
| Block 1                |
|  +------------------+  |
|  | Block Header     |  |
|  | Compressed Data  |  |
|  +------------------+  |
+========================+
|         ...            |
+========================+
```

### 4.1 Block Format

Each block consists of:

```
+---------------------+
| Block Header (64)   |  Size, hash, and Reed-Solomon parity
+---------------------+
| Compressed Data     |  LZMA compressed stream
+---------------------+
```

#### 4.1.1 Block Header Format

```
+-------------------------+
| Physical Block Size (8) |  Size with type flags in MSBs
+-------------------------+
| BLAKE3 Hash/CV (32)     |  Chaining value or root hash
+-------------------------+
| RS Parity (24)          |  Reed-Solomon parity bytes
+-------------------------+
```

**Size Field with Type Flags**:

- **Bits 63-62**: Type flags
    - **Bit 63 (MSB)**: 0 = Block header, 1 = Final trailer
    - **Bit 62**: For blocks: 0 = Full block, 1 = Partial block (only last block)
- **Bits 61-0**: Physical block size (up to 2^62 - 1 bytes)

For block headers (MSB = 0):

- **Bit 62 = 0**: Full block (uncompressed size = block_size from header)
- **Bit 62 = 1**: Partial block (only allowed as the last block)

**Examples**:

- 0x0000000000001000: Full block with 4096 bytes data
- 0x4000000000000800: Partial block with 2048 bytes data
- 0x8000000000000000: Final trailer (size field repurposed for total uncompressed)

#### 4.1.2 Compressed Data

- Raw LZMA stream data with end-of-stream marker (the distance-length pair of 0xFFFFFFFF, 2)
- Each block is completely independent with reset LZMA encoder state
- Prefilters (if used) are reset for each block with no state carried between blocks

#### 4.1.3 BLAKE3 Hash/Chaining Value

**BLAKE3 Hash/Chaining Value**:

- **For multi-block files**: The 32-byte chaining value computed with the appropriate input offset.
- **For single-block files**: The 32-byte BLAKE3 root hash computed.

**Note**: During streaming compression, the hasher processes data incrementally. At block
completion, the implementation must determine whether this is the final block:

- If more data follows: finalize as non-root chaining value
- If this is the only block: finalize as root hash

#### 4.1.4 Reed-Solomon Protection

Each block header includes 24 bytes of Reed-Solomon parity protecting both the size field
and the BLAKE3 hash/chaining value using RS(64,40) parameters (GF(2^8), n=64, k=40, t=12).

### 4.2 Block Size Requirements

**BLAKE3 Tree Structure Requirements**:

To maintain a valid BLAKE3 tree structure that supports efficient append operations:

- **Full blocks**: Have uncompressed size exactly equal to the block size specified in the header
- **Partial block**: Only the last block may be partial (uncompressed size < block_size)
- **Block size**: MUST be a power of 2 and at least 64 KiB

**Determining Uncompressed Size**:

- For full blocks (bit 62 = 0): uncompressed_size = block_size from header
- For partial blocks (bit 62 = 1): block must be uncompressed to get exact size

**Rationale**: BLAKE3's tree structure requires chunks to form a specific binary tree where left subtrees
are complete binary trees with power-of-2 chunks. By enforcing power-of-2 block sizes and requiring all
non-final blocks to be exactly that size, we ensure:

1. The BLAKE3 tree structure remains valid
2. Chaining values can be computed with correct input offsets
3. Append operations remain efficient when the last block is full

**Compression Ratio Trade-offs**:

The choice of block size directly impacts compression ratio:

- **Larger blocks**: Better compression ratio, more memory usage, less parallelization for medium inputs
- **Smaller blocks**: Lower compression ratio, less memory usage, more parallelization opportunities

**Optimal configuration**:

- Block size should be ≥ dictionary size for efficient compression
- Recommended block sizes: 1 MiB to 512 MiB depending on use case (must be power of 2)
- Consider memory usage: parallel decompression requires approximately (dict_size + block_size) × thread_count

## 5. Final Trailer Format

The final trailer provides whole-file integrity verification and is distinguished from block headers
by having the MSB set in its first field:

```
+---------------------+
| Total Uncompressed  |  (8 bytes, MSB = 1)
+---------------------+
| BLAKE3 Root Hash    |  (32 bytes)
+---------------------+
| Reed-Solomon Parity |  (24 bytes)
+---------------------+
```

### 5.1 Total Uncompressed Size with Trailer Flag

- **Bit 63 (MSB)**: Always 1 to indicate this is the final trailer
- **Bits 62-0**: Total size of all decompressed data in bytes (sum of all block uncompressed sizes)

Maximum representable uncompressed size: 2^63 - 1 bytes

### 5.2 BLAKE3 Root Hash

The final 256-bit BLAKE3 hash computed by properly merging all block chaining values according to
the BLAKE3 tree structure.

### 5.3 Reed-Solomon Error Correction

24 bytes of Reed-Solomon parity data protecting both the total uncompressed size and Blake3 root hash.
The 40 bytes (8 + 32) are treated as 40 message symbols, producing 24 parity symbols, for a total
codeword of 64 symbols.

Parameters:

- Field: GF(2^8)
- Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
- Code: RS(64,40,12)
- Generator: α = 2

**Encoding**: The 8-byte size and 32-byte Blake3 hash are treated as a sequence of 40 consecutive
bytes for Reed-Solomon encoding. No byte reordering or integer interpretation is performed.

**Decoding**: The code guarantees correction of up to 12 byte errors in the protected fields using
traditional unique decoding algorithms. Implementations MAY employ list decoding algorithms (such as
Sudan or Guruswami-Sudan) to attempt recovery from more than 12 errors, using the Blake3 hash of the
decompressed data to disambiguate between candidate codewords. When list decoding succeeds beyond the
traditional bound, implementations SHOULD indicate to the user that recovery was achieved with reduced
confidence, as the mathematical uniqueness guarantee no longer applies.

Reed-Solomon codes were chosen for their exceptional maturity and proven reliability. They have been
successfully deployed for decades in CD/DVD error correction, QR codes, satellite communications, and
RAID systems. The mathematics are thoroughly understood and battle-tested implementations are available.

## 6. Processing Requirements

### 6.1 Compression

1. Calculate Reed-Solomon parity for header and write protected header
2. For each block of input data:
    - Track cumulative uncompressed offset
    - Initialize BLAKE3 hasher with appropriate offset
    - Compress the block with LZMA while updating the hasher
    - Determine if this is a full or partial block
    - At block completion, determine finalization:
        - **If this is the first block and no more data follows** (single-block file):
          Create the hash as root hash.
        - **Otherwise** (multi-block file or more blocks coming):
          Create the hash as non-root hash (chaining value).
    - Calculate Reed-Solomon parity for size and hash
    - Set physical block size field with appropriate flags (MSB=0, bit 62 for full/partial)
    - Write block header with RS parity, then data
3. **For multi-block files**: Merge all block chaining values to compute root hash
   **For single-block files**: The root hash is already in the block header
4. Calculate Reed-Solomon parity for total size and root hash
5. Write final trailer with MSB=1 in size field

### 6.2 Decompression

#### Sequential Mode

1. Verify header Reed-Solomon codes and parse configuration including block size
2. Track number of full blocks processed
3. For each block:
    - Read first 64 bytes as potential block header
    - Apply Reed-Solomon correction if needed
    - Check MSB of size field:
        - If MSB=1, this is the final trailer, proceed to step 4
        - If MSB=0, this is a block header, continue
    - Extract actual physical block size (bits 61-0)
    - Determine block type from bit 62 (0 = full, 1 = partial)
    - Read and decompress block data
    - Verify chaining value against block header
    - Accumulate for final hash verification
4. Process final trailer:
    - Verify Reed-Solomon codes
    - Extract total uncompressed size (bits 62-0)
    - Merge all chaining values to compute expected root hash
    - Verify against trailer's root hash

#### Parallel Mode

1. Parse header including block size
2. Use physical block size to discover block boundary while streaming
   or scan all block headers to build offset table
3. Distribute blocks to worker threads
4. Each thread:
    - Decompresses its block
    - Verifies block header with RS correction
    - Returns chaining value and uncompressed data
5. Merge chaining values in proper tree order
6. Verify root hash against final trailer

### 6.3 Efficient Appending

To append data to an existing archive:

1. Scan existing blocks to collect:
    - Chaining values from block headers
    - Block type flags (full vs partial)
    - Count of full blocks
2. Check if last block is partial (bit 62 = 1 in size field):
    - If partial: Read and decompress the last block, combine with new data, recompress
    - If full: Proceed to step 3
3. Seek to before final trailer
4. Overwrite trailer with new blocks
5. For each new block:
    - Ensure all blocks except the last have exactly block_size bytes
    - Compute chaining value with correct offset
    - Set appropriate flags in physical block size
    - Write block header with RS parity and data
6. Update total uncompressed size
7. Merge all chaining values (old and new) for root hash
8. Write new final trailer with MSB=1

**Performance**:

- When last block is full: O(n) where n is number of blocks, not O(m) where m is data size
- When last block is partial: Requires recompressing the last block plus new data

### 6.4 Incremental Verification

The format supports three levels of verification:

1. **Block-level**: Each block's chaining value can be verified independently with RS correction
2. **Progressive**: Blocks can be verified as they stream without waiting for completion
3. **Full**: Final root hash verification confirms complete integrity

### 6.5 Single-Block File Handling

When a file consists of only one block, the BLAKE3 computation differs only in the
finalization step:

- The same hasher processes the uncompressed data
- Instead of creating a chaining value, a root hash is created
- This root hash goes in both the block header and the final trailer

This approach requires no buffering - only a different finalization method based on
whether more data follows.

## 7. Validation Strategy

The format provides multiple validation layers:

1. **Header Protection**: Reed-Solomon codes protect against header corruption
2. **LZMA Stream**: Built-in stream integrity checking
3. **Block Level**: Each block header provides RS-protected integrity verification
4. **Tree Structure**: BLAKE3 chaining values must form valid tree
5. **File Level**: Root hash verifies complete data integrity with RS protection
6. **Corruption Recovery**: Reed-Solomon codes can correct up to 12 bytes of corruption per protected field

## 8. Error Handling

### 8.1 Fatal Errors

Decoders MUST abort on:

- Invalid magic bytes
- Unsupported version
- Invalid configuration values
- Invalid block size (not power of 2 or < 64 KiB, except for the last block)
- Uncorrectable Reed-Solomon errors in header

### 8.2 Block-Level Errors

For each block, decoders SHOULD:

- Attempt Reed-Solomon correction on corrupted headers
- Report blocks that fail integrity checks after correction
- Verify that only the last block has the partial flag set
- Implementation MAY continue processing remaining blocks if possible

### 8.3 Recovery Capabilities

With Reed-Solomon protection, the format supports:

- **Header recovery**: Up to 12 bytes of corruption (sic!) in the 10-byte header payload
- **Block recovery**: Up to 12 bytes of corruption in each 40-byte block header payload
- **Trailer recovery**: Up to 12 bytes of corruption in the 40-byte trailer payload
- **Partial validation**: Individual blocks can be verified independently
- **Selective recovery**: Valid blocks can be extracted even if others are corrupted
- **Progressive validation**: Corruption detected early in streaming scenarios

## 9. Security Considerations

### 9.1 Memory Safety

- Decoders MUST validate all size fields before allocation
- Decoders MUST prevent integer overflow in offset calculations
- Decoders MUST validate block size is power of 2 and within valid range
- Decoders MUST verify MSB flags to distinguish headers from trailers

### 9.2 Resource Limits

- Decoders SHOULD implement configurable memory usage limits
- Parallel decoders SHOULD limit thread pool size
- Maximum physical block size is limited to 2^62 - 1 bytes
- Maximum total uncompressed size is limited to 2^63 - 1 bytes

### 9.3 Tree Structure Integrity

- Decoders MUST verify block offsets form valid BLAKE3 tree
- Chaining values MUST be computed with correct input offsets
- Tree merging MUST follow BLAKE3 specifications exactly
- Block sizes MUST follow the power-of-2 requirements
- Only the last block may be partial

### 9.4 Cryptographic Considerations

- BLAKE3 provides 128-bit collision resistance and 256-bit preimage resistance
- RS protection prevents malicious hash corruption
- The format does not provide encryption or authentication
- The format does not protect against intentional tampering without an outside
  communication channel for the authentication of the hash value

## 10. Implementation Notes

### 10.1 BLAKE3 Tree Structure

The BLAKE3 tree structure requires careful handling. The power-of-2 block size requirement
ensures that blocks align properly with BLAKE3's chunk boundaries and tree structure.
Please read the BLAKE3 paper (see section 2.1) and the hazmat module documentation of the Rust crate.

https://docs.rs/blake3/latest/blake3/hazmat/index.html

### 10.2 Streaming Processing Benefits

The format supports full streaming operation:

- Compression without knowing final size
- Decompression without seeking
- Pipe-friendly operation
- Simple block/trailer distinction via MSB flag

### 10.3 Parallel Processing Benefits

With block headers, the format enables:

- **Parallel compression**: Each thread computes its block's chaining value independently
- **Parallel decompression**: Threads decompress and verify blocks concurrently
- **Parallel hashing**: No sequential hash computation bottleneck
- **Parallel validation**: Block integrity checked independently with RS correction

### 10.4 Reed-Solomon Implementation

The RS(64,40) code provides robust error correction:

- Can correct up to 12 byte errors in the 40-byte payload
- Same code structure for blocks and trailer
- Shortened RS(34,10) for header derived from same base code
- Efficient implementations available in many languages

## 11. Design Rationale and Critical Analysis

This section addresses potential criticisms of the Streaming-LZMA format design and explains the reasoning behind key
architectural decisions.

### 11.1 Block Headers with RS Protection: The Key Innovation

**Criticism**: Adding 64 bytes per block (24 for RS parity) seems excessive when other formats use minimal or no
per-block metadata.

**Response**: The block header design with Reed-Solomon protection represents a fundamental shift in compression format
philosophy, providing capabilities that justify the overhead:

**Benefits**:

1. **Robust Recovery**: RS codes can correct up to 12 bytes of corruption per block header, enabling recovery from
   significant damage that would be fatal in other formats.

2. **Efficient Append Operations**: When the last block is full, appending is O(n) where n is block count. Even when
   the last block requires recompression, only one block needs processing rather than the entire file.

3. **True Parallel Hashing**: BLAKE3's tree structure was designed for parallelism, but most formats can't exploit it.
   Our block headers enable linear speedup with core count for both compression and decompression.

4. **Progressive Validation**: Users can verify data integrity as it streams, rather than waiting for complete
   download. Critical for large transfers and unreliable networks.

5. **Granular Corruption Detection**: Instead of "file corrupt" we can report "blocks 47 and 892 corrupt but
   recoverable, others valid".
   This enables partial recovery and targeted retransmission.

6. **Sigil-Based Recovery**: The protected headers and trailer act as synchronization points for recovery tools,
   making it possible to reconstruct damaged archives even with missing sections.

### 11.2 Power-of-2 Block Size Requirement

**Criticism**: Why restrict block sizes to powers of 2? This seems unnecessarily restrictive.

**Response**: This requirement directly follows from BLAKE3's tree structure design:

**BLAKE3 Tree Compatibility**: BLAKE3's binary tree structure requires that left subtrees contain power-of-2
chunks. By making our blocks align with this structure (and ensuring all non-final blocks are exactly the
configured size), we maintain a valid BLAKE3 tree that supports:

- Correct chaining value computation
- Efficient append operations
- Proper tree merging for the root hash

**Simplicity**: Power-of-2 sizes are natural for binary systems and simplify implementation logic.

### 11.3 LZMA vs LZMA2 Decision

**Criticism**: Why use LZMA instead of its successor LZMA2, which adds features like uncompressed chunks and better
streaming support?

**Response**: Empirical testing revealed that LZMA consistently outperforms LZMA2 in our format:

**Compression Efficiency**: Across diverse test data (Linux kernel sources, executables, JPEG images), LZMA produced
consistently smaller output than LZMA2. The overhead from LZMA2's chunk headers and control bytes negates its
theoretical advantages.

**Simplicity Benefit**: LZMA's simpler structure reduces implementation complexity without sacrificing functionality.
The primary LZMA2 advantage - switching between compressed and uncompressed chunks - provides minimal benefit when
the entire block structure already provides natural boundaries.

**Memory Trade-offs**: While LZMA2's chunking can reduce memory usage during compression, our block-based design
already provides memory-bounded operation. The encoder only needs to buffer one block at a time if streaming is needed,
or don't need to buffer at all if seeking is possible (for example when writing into files), making LZMA2's fine-grained
chunking redundant.

### 11.4 Cryptographic Hash "Overkill"

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

### 11.5 Reed-Solomon at Every Level

**Criticism**: Protecting every single block's metadata with Reed-Solomon codes is overkill. Most corruption affects
data, not metadata.

**Response**: This design creates a very high level of robustness:

**The Six-Factor Integrity System**:

1. Reed-Solomon protects the file header
2. LZMA stream has internal checks
3. Each block has a cryptographic chaining value
4. Each block header is RS-protected
5. The tree structure must be valid
6. The root hash with RS protection provides final verification

For undetected corruption to occur, you need:

- Header corruption that defeats RS correction
- LZMA corruption that still decompresses
- Produces data that happens to hash correctly
- The corrupted hash defeats RS correction
- The tree structure remains valid
- The root hash still matches

Combined probability: essentially impossible

**Practical Benefits**:

- **Tape Storage**: RS codes handle the burst errors common in tape media
- **Network Transmission**: Can recover from packet corruption without retransmission
- **Long-term Archive**: Provides confidence for decades-long storage
- **Disaster Recovery**: Even severely damaged files may be partially recoverable

### 11.6 Simplified Structure Benefits

The removal of the end-of-blocks marker and use of MSB flags creates a cleaner design:

- **Simpler parsing**: Single bit check distinguishes blocks from trailer
- **No special markers**: No need for reserved byte sequences
- **Consistent structure**: All metadata protected by same RS(64,40) code
- **Efficient detection**: Can quickly identify structure type from first 8 bytes

### 11.7 BLAKE3's Perfect Fit

The choice of BLAKE3 becomes even more justified with this design:

- **Tree Mode**: Native support for our chaining value approach
- **Performance**: Faster than CRC32 with SIMD
- **Security**: Cryptographic strength for content addressing
- **Simplicity**: Single algorithm for both blocks and file

### 11.8 Summary

Streaming-LZMA makes deliberate trade-offs:

- **Small overhead** (64 bytes per block) for very high robustness
- **Added complexity** for new capabilities
- **Comprehensive protection** for maximum integrity

The format excels at:

- Large-scale data processing (parallel everything)
- Incremental operations (efficient append when last block is full)
- Robust integrity (six-factor validation)
- Progressive validation (streaming verification)

These capabilities are to our knowledge unique in the compression format landscape. No other format combines:

- Streaming operation
- Parallel processing at this level
- Efficient append operations (when last block is full)
- Per-block validation with error correction
- Cryptographic integrity with error correction at multiple levels

## 12. Acknowledgements

The Streaming-LZMA format builds upon decades of compression research and development. We acknowledge:

- **Igor Pavlov** for creating the LZMA algorithm
- **Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko** for developing BLAKE3 and specifically designing
  its tree mode for parallel processing
- **Irving S. Reed and Gustave Solomon** for their pioneering work on error correction codes
- **The XZ Utils project** (Lasse Collin and contributors) for advancing LZMA-based compression
- **The lzip project** (Antonio Diaz Diaz) for demonstrating the value of simplicity
- **The Bao project** for showing practical applications of BLAKE3's tree structure
- The broader compression community for continuous innovation in data compression techniques

## 13. Intellectual Property Notice

### 13.1 Specification License

This specification is placed in the **public domain**. Anyone may freely implement, use, modify, or distribute this
specification without restriction.

### 13.2 Patent Disclaimer

To the best of the authors' knowledge, the Streaming-LZMA format as specified in this document is not encumbered by
patents. The core technologies are believed to be patent-free.

- LZMA algorithm is believed to be patent-free and has been widely implemented without patent claims for over 20 years
- Blake3 is explicitly released under CC0 (public domain) with no known patent encumbrances
- Reed-Solomon codes have been in public use since 1960 with expired foundational patents
- BCJ filters are well-established techniques without known patent claims

**This document does not constitute legal advice**. Implementers are responsible for their own patent review and risk
assessment. The authors make no warranties regarding patent status and assume no liability for implementations based
on this specification.

### 13.3 Trademark Notice

"Streaming-LZMA" is not a registered trademark. The name may be used freely to identify implementations of this
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
fedcba980100003e5d10700649933ab752097563
d703b263a0e17a5e4824f77d2ff1000000000000
0080af1349b9f5f9a1a6a0404dea36dcc9499bcb
25c9adc112b7cc9a93cae41f3262b6b17928a5ac
89997f71c2a558ba97988ac959e411b42a81
```

Hexdump of a single block file with a single compressed zero byte with the following configuration:

- Prefilter: BCJ X86
- LZMA LC: 3
- LZMA LP: 0
- LZMA PB: 2
- LZMA Dictionary size exponent: 30
- Block size exponent: 11

```
fedcba980100011f5d1ef776ff58259da3edb40b
dc53ceb8a7b4e2cf6ec95dc0e75b0b0000000000
00402d3adedff11b61f14c886e35afa036736dcd
87a74d27b5c1510225d0f592e213e82fafd5acdf
4327b2bd4c3f26af861437d52dde78e034b00000
41fef7ffffe000800001000000000000802d3ade
dff11b61f14c886e35afa036736dcd87a74d27b5
c1510225d0f592e213f2cf908ca3803a1f9f80b8
2f1873c4581d5507446794e32e
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

#### A.3.1 - Test vectors for RS(64,40)

Test 1:
Data:    00000000000000000000000000000000000000000000000000000000000000000000000000000000
Parity:  000000000000000000000000000000000000000000000000

Test 2:
Data:    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
Parity:  e81d42b0548bfb1c5e9d0475a75446c6bda44e0b8ea6e459

Test 3:
Data:    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627
Parity:  9fb10923191a0659292e6e7c5ee8fbf0111329eb8bdaefe8

#### A.3.2 - Test vectors for RS(34,10)

Test 1:
Data:    00000000000000000000
Parity:  000000000000000000000000000000000000000000000000

Test 2:
Data:    ffffffffffffffffffff
Parity:  a13722e7a3f27fe7702b64bdb2fad7bbb4eff74838d4c490

Test 3:
Data:    00010203040506070809
Parity:  39e7d8f19efea4e2eadeb2547f7984bfa1949c9f75cddd90

#### A.3.2 - Minimal Python Implementation

Using Python 3, numpy and galois:

```python
import galois
import numpy as np

# Create the field with exact primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
GF = galois.GF(2**8, irreducible_poly=0x11d)

# Verify primitive element is 2
alpha = GF.primitive_element
assert alpha == 2

# Build generator polynomial for RS(64,40) - roots at α^1 through α^24
g = galois.Poly([1], field=GF)
x = galois.Poly([1, 0], field=GF)
for i in range(1, 25):  # α^1 through α^24 (since 2t = 24)
    g = g * (x - alpha**i)

def rs_encode_64_40(data_bytes):
    """
    Encode 40-byte data with RS(64,40) protection.
    
    Parameters:
    - Field: GF(2^8)
    - Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
    - Code: RS(64,40,12) - can correct up to 12 byte errors
    - Generator: α = 2
    
    Args:
        data_bytes: Exactly 40 bytes of data
        
    Returns:
        64 bytes total: [40 bytes data || 24 bytes parity]
    """
    assert len(data_bytes) == 40, "Data must be exactly 40 bytes"
    
    # Convert bytes to galois field elements
    data_list = list(data_bytes)
    data_gf = GF(data_list)
    
    # Create polynomial from data (highest degree first for galois library)
    data_poly = galois.Poly(data_gf[::-1], field=GF)
    
    # Shift by parity length (multiply by x^24)
    shifted = data_poly * galois.Poly([1] + [0]*24, field=GF)
    
    # Compute remainder when divided by generator polynomial
    _, remainder = divmod(shifted, g)
    
    # Extract parity coefficients (reverse to get lowest degree first)
    parity_coeffs = remainder.coeffs[::-1] if remainder.degree >= 0 else []
    parity = np.zeros(24, dtype=np.uint8)
    parity[:len(parity_coeffs)] = [int(x) for x in parity_coeffs]
    
    return bytes(data_bytes) + bytes(parity)

def rs_encode_34_10(data_bytes):
    """
    Encode 10-byte data with shortened RS(34,10) protection.
    
    This is a shortened version of RS(64,40) used for the file header.
    
    Parameters:
    - Same field and generator as RS(64,40)
    - Shortened to handle 10 bytes data + 24 bytes parity = 34 bytes total
    - Still corrects up to 12 byte errors
    
    Args:
        data_bytes: Exactly 10 bytes of data (file header payload)
        
    Returns:
        34 bytes total: [10 bytes data || 24 bytes parity]
    """
    assert len(data_bytes) == 10, "Data must be exactly 10 bytes"
    
    # For shortened code, prepend (40-10)=30 zero bytes to make 40 bytes
    padded_data = bytes(30) + data_bytes
    
    # Encode with full RS(64,40) code
    full_codeword = rs_encode_64_40(padded_data)
    
    # Remove first (64-34)=30 bytes to get shortened codeword
    return full_codeword[30:]

def test_rs_implementations():
    # Test RS(64,40) with test vectors
    data1 = bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000")
    expected_parity1 = bytes.fromhex("000000000000000000000000000000000000000000000000")
    codeword = rs_encode_64_40(data1)
    assert codeword[40:] == expected_parity1

    data2 = bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    expected_parity2 = bytes.fromhex("e81d42b0548bfb1c5e9d0475a75446c6bda44e0b8ea6e459")
    codeword = rs_encode_64_40(data2)
    assert codeword[40:] == expected_parity2

    data3 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627")
    expected_parity3 = bytes.fromhex("9fb10923191a0659292e6e7c5ee8fbf0111329eb8bdaefe8")
    codeword = rs_encode_64_40(data3)
    assert codeword[40:] == expected_parity3

    # Test RS(34,10) with test vectors
    data1 = bytes.fromhex("00000000000000000000")
    expected_parity1 = bytes.fromhex("000000000000000000000000000000000000000000000000")
    codeword = rs_encode_34_10(data1)
    assert codeword[10:] == expected_parity1

    data2 = bytes.fromhex("ffffffffffffffffffff")
    expected_parity2 = bytes.fromhex("a13722e7a3f27fe7702b64bdb2fad7bbb4eff74838d4c490")
    codeword = rs_encode_34_10(data2)
    assert codeword[10:] == expected_parity2

    data3 = bytes.fromhex("00010203040506070809")
    expected_parity3 = bytes.fromhex("39e7d8f19efea4e2eadeb2547f7984bfa1949c9f75cddd90")
    codeword = rs_encode_34_10(data3)
    assert codeword[10:] == expected_parity3

if __name__ == "__main__":
    test_rs_implementations()
```

Note: Do NOT use galois.ReedSolomon(64, 40) as it expects primitive codes. The implementation above correctly handles
the systematic encoding used in the Streaming-LZMA format.

## Appendix B: Reference Implementation

A reference implementation in Rust is available at https://github.com/hasenbanck/slz

## Appendix C: Recommended File Extension

Files using this format SHOULD use the extension `.slz`.

## Revision History

- Version 0.5 (2025-08-18): Major revision for improved robustness:
    - Moved block trailer to header with RS(64,40) protection;
    - Added RS(34,10) protection to file header;
    - Removed Delta prefilter and end-of-blocks marker;
    - Added capabilities field for future extensibility;
    - Use MSB flags to distinguish block headers from final trailer
    - Renamed compressed block size to physical block size
- Version 0.4 (2025-08-17): Added block trailers with chaining values and Reed-Solomon protection
- Version 0.3 (2025-08-15): Initial specification
