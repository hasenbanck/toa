# Streaming-LZMA Archive Format Specification

Version 0.4

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

**Efficient Append Operations**: The inclusion of BLAKE3 chaining values per block enables O(n) append operations
where n is the number of blocks, rather than O(m) where m is the total data size. This makes incremental backups
and log aggregation highly efficient.

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
|      Header      |  (Variable: 6-9 bytes)
+==================+
|      Blocks      |  (Variable: 0 or more blocks with trailers, but always ending with a end-of-blocks marker)
+==================+
|   Final Trailer  |  (Fixed: 72 bytes)
+==================+
```

## 3. Header Format

The header contains format identification and compression configuration:

```
+------+------+------+------+
| 0xFE | 0xDC | 0xBA | 0x98 |  Magic bytes (4 bytes)
+------+------+------+------+
|    Version   | Prefilter  |  Version and prefilter (2 bytes)
+------+------+------+------+
|   LZMA Properties         |  (2 bytes)
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

### 3.3 Prefilter Selection

One byte indicating the optional prefilter:

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
- 0x0A-0xFF: Reserved

The prefilters are the same as used by LZMA SDK and liblzma.

### 3.4 LZMA Properties

Two bytes encoding LZMA compression parameters:

- **Byte 0**: Properties byte encoding (pb * 5 + lp) * 9 + lc
    - lc: number of literal context bits (0-8)
    - lp: number of literal position bits (0-4)
    - pb: number of position bits (0-4)
- **Byte 1**: Dictionary size as power of 2 (size = 2^(n+16))

Valid dictionary sizes range from 64 KiB (n=0) to 2 GiB (n=15).

Examples:

- n=0: 2^16 = 64 KiB
- n=8: 2^24 = 16 MiB
- n=15: 2^31 = 2 GiB

**Note on LZMA parameters**: While the default LZMA parameters (lc=3, lp=0, pb=2) work
well for most data, BCJ filters benefit from adjusted parameters. For example:

- ARM64 executable: lc=2,lp=2,pb=2
- RISC-V executable: lc=2,lp=2,pb=2
- RISC-V executable with compressed instructions: lc=3,lp=1,pb=2
- x86 executables: lc=3,lp=0,pb=2 (default)

### 3.5 Prefilter Properties

Filter-specific configuration parameters:

**Delta filter** (1 byte):

- Byte 0: Distance minus 1 (0x00 represents distance 1, 0xFF represents distance 256)

**BCJ filters**: No additional properties (offset is always 0)

## 4. Blocks Section

The blocks section contains compressed blocks, each with its own trailer.
The blocks section ends with an end-of-blocks marker (8 * 0x00).

```
+========================+
| Block 0                |
|  +------------------+  |
|  | Size (8B)        |  |
|  | Compressed Data  |  |
|  | Block Trailer    |  |
|  +------------------+  |
+========================+
| Block 1                |
|  +------------------+  |
|  | Size (8B)        |  |
|  | Compressed Data  |  |
|  | Block Trailer    |  |
|  +------------------+  |
+========================+
|         ...            |
+========================+
| End-of-blocks marker   |
| (8 * 0x00)             |
+========================+
```

### 4.1 Block Format

Each block consists of:

```
+---------------------+
| Compressed Size (8) |  Compressed data size in bytes
+---------------------+
| Compressed Data     |  LZMA compressed stream
+---------------------+
| Block Trailer (72)  |  Integrity and metadata
+---------------------+
```

#### 4.1.1 Size Field

- **Size** (8 bytes): Compressed size of the block data in bytes, stored as little-endian uint64
- Minimum size: 1 B (size field value 0x0000000000000001)
- Maximum size: 16 EiB - 1 B (size field value 0xFFFFFFFFFFFFFFFF)
- Zero-length blocks are not permitted

#### 4.1.2 Compressed Data

- Raw LZMA stream data with end-of-stream marker (the distance-length pair of 0xFFFFFFFF, 2)
- Each block is completely independent with reset LZMA encoder state
- Prefilters (if used) are reset for each block with no state carried between blocks

#### 4.1.3 Block Trailer

Each block includes a 72-byte trailer for integrity and metadata:

```
+---------------------+
| Uncompressed Size   |  (8 bytes, little-endian)
+---------------------+
| BLAKE3 Hash/CV      |  (32 bytes, see note)
+---------------------+
| Reed-Solomon Parity |  (32 bytes)
+---------------------+
```

**Uncompressed Size**: Size of the block after decompression in bytes.

**BLAKE3 Hash/Chaining Value**:

- **For multi-block files**: The 32-byte chaining value computed with the appropriate input offset.
- **For single-block files**: The 32-byte BLAKE3 root hash computed.

**Note**: During streaming compression, the hasher processes data incrementally. At block
completion, the implementation must determine whether this is the final block:

- If more data follows: finalize as non-root chaining value
- If this is the only block: finalize as root hash

**Reed-Solomon Parity**: 32 bytes of Reed-Solomon parity protecting the BLAKE3 chaining value
using the same parameters as the final trailer (GF(2^8), n=64, k=32, t=16).

### 4.2 Block Size Requirements and Recommendations

**BLAKE3 Alignment Requirement**:

All blocks except the last block MUST have uncompressed sizes that are multiples of 1024 bytes (1 KiB).
This requirement ensures proper BLAKE3 chunk boundary alignment when using input offsets for parallel hashing.

- **All blocks except last**: Uncompressed size MUST be divisible by 1024
- **Last block**: May have any uncompressed size (no alignment required)
- **Rationale**: BLAKE3's `set_input_offset()` requires offsets to be chunk-aligned (1024-byte boundaries)

**Compression Ratio Trade-offs**:

The choice of block size directly impacts compression ratio:

- **Single block**: Maximum compression ratio, limited parallelization
- **Multiple blocks**: Reduced compression ratio due to dictionary reset at boundaries, but enables parallel processing

**Optimal configuration**:

- Block size should be ≥ dictionary size for efficient compression
- Recommended block sizes: 1 MiB to 64 MiB depending on use case (must be 1 KiB-aligned)
- Consider memory usage: parallel decompression requires approximately (dict_size + block_size) × thread_count

### 4.3 End-of-Blocks Marker

The sequence `0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00` indicates the end of blocks. Since zero-length blocks are
invalid, this sequence unambiguously marks the end of the blocks section.

## 5. Final Trailer Format

The final trailer provides whole-file integrity verification:

```
+---------------------+
| Total Uncompressed  |  (8 bytes, little-endian)
+---------------------+
| BLAKE3 Root Hash    |  (32 bytes)
+---------------------+
| Reed-Solomon Parity |  (32 bytes)
+---------------------+
```

### 5.1 Total Uncompressed Size

Total size of all decompressed data in bytes (sum of all block uncompressed sizes).

### 5.2 BLAKE3 Root Hash

The final 256-bit BLAKE3 hash computed by properly merging all block chaining values according to
the BLAKE3 tree structure.

### 5.3 Reed-Solomon Error Correction

32 bytes of Reed-Solomon parity data protecting the Blake3 hash. The 32 byte hash is treated as 32 message symbols,
producing 32 parity symbols, for a total codeword of 64 symbols.

Parameters:

- Field: GF(2^8)
- Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
- Code: (n=64, k=32, t=16)
- Generator: α = 2

**Encoding**: The 32-byte Blake3 hash is treated as a sequence of 32 consecutive bytes [h₀, h₁, ..., h₃₁] for
Reed-Solomon encoding. No byte reordering or integer interpretation is performed.

**Decoding**: The code guarantees correction of up to 16 byte errors in the hash field using traditional unique
decoding algorithms. Implementations MAY employ list decoding algorithms (such as Sudan or Guruswami-Sudan) to
attempt recovery from more than 16 errors, using the Blake3 hash of the decompressed data to disambiguate between
candidate codewords. When list decoding succeeds beyond the traditional bound, implementations SHOULD indicate to
the user that recovery was achieved with reduced confidence, as the mathematical uniqueness guarantee no longer applies.

Reed-Solomon codes were chosen for their exceptional maturity and proven reliability. They have been successfully
deployed for decades in CD/DVD error correction, QR codes, satellite communications, and RAID systems. The mathematics
are thoroughly understood and battle-tested implementations are available.

## 6. Processing Requirements

### 6.1 Compression

1. Write header with appropriate configuration
2. For each block of input data:
    - Track cumulative uncompressed offset
    - Initialize BLAKE3 hasher with appropriate offset
    - Compress the block with LZMA while updating the hasher
    - At block completion, determine finalization:
        - **If this is the first block and no more data follows** (single-block file):
          Create the hash as root hash.
        - **Otherwise** (multi-block file or more blocks coming):
          Create the hash as non-root hash (chaining value).
    - Calculate Reed-Solomon parity of the hash/CV
    - Write: compressed size, compressed data, block trailer
3. Write end-of-blocks marker
4. **For multi-block files**: Merge all block chaining values to compute root hash
   **For single-block files**: The root hash is already in the block trailer
5. Calculate Reed-Solomon parity of root hash
6. Write final trailer

### 6.2 Decompression

#### Sequential Mode

1. Verify header and parse configuration
2. For each block until end-of-blocks marker:
    - Read compressed size
    - If size is zero, end block processing
    - Read and decompress block data
    - Read block trailer
    - Verify chaining value (with RS correction if needed)
    - Accumulate for final hash verification
3. Merge all chaining values to compute expected root hash
4. Verify against final trailer (with RS correction if needed)

#### Parallel Mode

1. Parse header
2. Scan all block headers to build offset table or
   dispatch block to worker threads once sequentially read
3. Distribute blocks to worker threads
4. Each thread:
    - Decompresses its block
    - Verifies block trailer
    - Returns chaining value and uncompressed data
5. Merge chaining values in proper tree order
6. Verify root hash against final trailer

### 6.3 Efficient Appending

To append data to an existing archive:

1. Scan existing blocks to collect:
    - Chaining values from block trailers
    - Uncompressed sizes and offsets
2. Seek to end-of-blocks marker
3. Overwrite marker and final trailer with new blocks
4. For each new block:
    - Compute chaining value with correct offset
    - Write block with trailer
5. Merge all chaining values (old and new) for root hash
6. Write new end-of-blocks marker and final trailer

**Performance**: O(n) where n is number of blocks, not O(m) where m is data size

### 6.4 Incremental Verification

The format supports three levels of verification:

1. **Block-level**: Each block's chaining value can be verified independently
2. **Progressive**: Blocks can be verified as they stream without waiting for completion
3. **Full**: Final root hash verification confirms complete integrity

### 6.5 Single-Block File Handling

When a file consists of only one block, the BLAKE3 computation differs only in the
finalization step:

- The same hasher processes the uncompressed data
- Instead of creating a chaining value, a root hash is created
- This root hash goes in both the block trailer and the final trailer

This approach requires no buffering - only a different finalization method based on
whether more data follows.

## 7. Validation Strategy

The format provides multiple validation layers:

1. **LZMA Stream**: Built-in stream integrity checking
2. **Block Level**: Each block trailer provides RS-protected integrity verification
3. **Tree Structure**: BLAKE3 chaining values must form valid tree
4. **File Level**: Root hash verifies complete data integrity
5. **Corruption Recovery**: Reed-Solomon codes can correct up to 16 bytes of hash corruption

## 8. Error Handling

### 8.1 Fatal Errors

Decoders MUST abort on:

- Invalid magic bytes
- Unsupported version
- Invalid configuration values

### 8.2 Block-Level Errors

For each block, decoders SHOULD:

- Attempt Reed-Solomon correction on corrupted chaining values
- Report blocks that fail integrity checks
- Implementation MAY continue processing remaining blocks if possible

### 8.3 Recovery Capabilities

With block trailers, the format supports:

- **Partial validation**: Individual blocks can be verified
- **Selective recovery**: Valid blocks can be extracted even if others are corrupted
- **Progressive validation**: Corruption detected early in streaming scenarios
- **Hash repair**: RS codes can recover from hash corruption at both block and file level

## 9. Security Considerations

### 9.1 Memory Safety

- Decoders MUST validate all size fields before allocation
- Decoders MUST prevent integer overflow in offset calculations

### 9.2 Resource Limits

- Decoders SHOULD implement configurable memory usage limits
- Parallel decoders SHOULD limit thread pool size

### 9.3 Tree Structure Integrity

- Decoders MUST verify block offsets form valid BLAKE3 tree
- Chaining values MUST be computed with correct input offsets
- Tree merging MUST follow BLAKE3 specifications exactly

### 9.4 Cryptographic Considerations

- BLAKE3 provides 128-bit collision resistance and 256-bit preimage resistance
- RS protection prevents malicious hash corruption
- The format does not provide encryption or authentication
- The format does not protect against intentional tampering without an outside
  communication channel for the authentication of the hash value

## 10. Implementation Notes

### 10.1 BLAKE3 Tree Structure

The BLAKE3 tree structure requires careful handling. Please read the BLAKE3 paper (see section 2.1)
and the hazmat module documentation of the Rust crate.

https://docs.rs/blake3/latest/blake3/hazmat/index.html

### 10.2 Streaming Processing Benefits

The format supports full streaming operation:

- Compression without knowing final size
- Decompression without seeking
- Pipe-friendly operation

### 10.2 Parallel Processing Benefits

With block trailers, the format enables:

- **Parallel compression**: Each thread computes its block's chaining value independently
- **Parallel decompression**: Threads decompress and verify blocks concurrently
- **Parallel hashing**: No sequential hash computation bottleneck
- **Parallel validation**: Block integrity checked independently

### 10.3 Append Performance

Example for a 10 GB file with 1 MB blocks (10,000 blocks):

- **Without chaining values**: Read and hash 10 GB of data
- **With chaining values**: Read 720 KB of trailers, merge trees
- **Speedup**: ~14,000× faster

## 11. Design Rationale and Critical Analysis

This section addresses potential criticisms of the Streaming-LZMA format design and explains the reasoning behind key
architectural decisions.

### 11.1 Block Trailers: The Key Innovation

**Criticism**: Adding 72 bytes per block seems excessive when other formats use minimal or no per-block metadata.

**Response**: The block trailer design represents a fundamental shift in compression format philosophy, providing
capabilities that justify the overhead:

**Transformative Benefits**:

1. **O(n) Append Operations**: Traditional formats require O(m) operations where m is file size. With chaining values,
   appending becomes O(n) where n is block count. For large archives, this changes append from impractical to instant.

2. **True Parallel Hashing**: BLAKE3's tree structure was designed for parallelism, but most formats can't exploit it.
   Our block trailers enable linear speedup with core count for both compression and decompression.

3. **Progressive Validation**: Users can verify data integrity as it streams, rather than waiting for complete
   download. Critical for large transfers and unreliable networks.

4. **Granular Corruption Detection**: Instead of "file corrupt" we can report "blocks 47 and 892 corrupt, others valid".
   This enables partial recovery and targeted retransmission.

**Overhead Analysis**:

For 1 MB blocks on a 1 TB file:

- Overhead: 72 MB (0.007%)
- Benefit: 1000× faster appends, 16× faster parallel hashing

The overhead is negligible while the performance gains are transformative.

### 11.2 LZMA vs LZMA2 Decision

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

This decision validates the approach taken by the LZIP format, which similarly chose LZMA over LZMA2 for comparable
reasons.

### 11.3 Cryptographic Hash "Overkill"

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

### 11.4 Reed-Solomon at Every Level

**Criticism**: Protecting every single block's hash with Reed-Solomon codes is overkill. Most corruption affects data,
not metadata.

**Response**: This design creates an high level of robustness:

**The Five-Factor Integrity System**:

1. LZMA stream has internal checks
2. Each block has a cryptographic chaining value
3. Each chaining value is RS-protected
4. The tree structure must be valid
5. The root hash provides final verification

For undetected corruption to occur, you need:

- LZMA corruption that still decompresses
- Produces data that happens to hash correctly
- The corrupted hash forms a valid RS codeword
- The tree structure remains valid
- The root hash still matches

Combined probability: essentially impossible

**Practical Benefits**:

- **Tape Storage**: RS codes handle the burst errors common in tape media
- **Network Transmission**: Can recover from packet corruption without retransmission
- **Long-term Archive**: Provides confidence for decades-long storage

### 11.5 BLAKE3's Perfect Fit

The choice of BLAKE3 becomes even more justified with this design:

- **Tree Mode**: Native support for our chaining value approach
- **Performance**: Faster than CRC32 with SIMD
- **Security**: Cryptographic strength for content addressing
- **Simplicity**: Single algorithm for both blocks and file

### 11.6 Summary

Streaming-LZMA makes deliberate trade-offs:

- **Small overhead** for considerable performance gains
- **Added complexity** for new capabilities
- **Comprehensive protection** for strong integrity

The format excels at:

- Large-scale data processing (parallel everything)
- Incremental operations (efficient append)
- Robust integrity (five-factor validation)
- Progressive validation (streaming verification)

These capabilities are to our knowledge unique in the compression format landscape. No other format combines:

- Streaming operation
- Parallel processing at this level
- Inexpensive append operations
- Per-block validation
- Cryptographic integrity with error correction

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
- BCJ filters and Delta encoding are well-established techniques without known patent claims

**This document does not constitute legal advice**. Implementers are responsible for their own patent review and risk
assessment. The authors make no warranties regarding patent status and assume no liability for implementations based
on this specification.

### 13.3 Trademark Notice

"Streaming-LZMA" is not a registered trademark. The name may be used freely to identify implementations of this
specification.

## Appendix A: Test Vectors

### A.1 Minimal File

Hexdump of a minimal Streaming-LZMA file using LZMA (lc: 3 lp: 0 pb: 2, dictionary size log2: 16) + no prefilter and no
content:

```
fedcba9801005d000000000000000000
0000000000000000af1349b9f5f9a1a6
a0404dea36dcc9499bcb25c9adc112b7
cc9a93cae41f3262cedfc1cc789afb17
6bf1fb71a6756a5b315bdbc2322f987f
f3aa7b0c7c2a6a7d
```

Hexdump of a minimal Streaming-LZMA file using LZMA (lc: 3 lp: 0 pb: 2, dictionary size log2: 30) + Delta prefilter
(distance: 32) and one zero byte as content:

```
fedcba9801011f5d0e0b000000000000
00000041fef7ffffe000800001000000
000000002d3adedff11b61f14c886e35
afa036736dcd87a74d27b5c1510225d0
f592e213c213b18ea038cbd9669481d7
382c07d10c82c200979933423a3340c2
48382018000000000000000001000000
000000002d3adedff11b61f14c886e35
afa036736dcd87a74d27b5c1510225d0
f592e213c213b18ea038cbd9669481d7
382c07d10c82c200979933423a3340c2
48382018
```

### A.2 Block Chaining Example

For a 3-block file, the chaining value computation:

```
# Block 0: offset=0, size=1024
cv_0 = BLAKE3(data_0, offset=0, non_root)

# Block 1: offset=1024, size=1024  
cv_1 = BLAKE3(data_1, offset=1024, non_root)

#Block 2: offset=2048, size=512
cv_2 = BLAKE3(data_2, offset=2048, non_root)

root = merge_tree(cv_0, cv_1, cv_2, root=true)
```

### A.3 Reed-Solomon Implementation

The reference implementation provides a stack-only and efficient Reed-Solomon
implementation written in Rust, which code is in the public domain.

#### A.3.1 - Test vectors

Test 1:
Data:    0000000000000000000000000000000000000000000000000000000000000000
Parity:  0000000000000000000000000000000000000000000000000000000000000000

Test 2:
Data:    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
Parity:  caabc74d87d23ad8a0a2bff5134bf7499e1b2859fb692e40b8d8e6fa8bfb5620

Test 3:
Data:    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Parity:  d8e4dab6534b241cb9afcb999503ec2d8c393a30f96e719970cee1d547f75acb

Test 4:
Data:    dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
Parity:  0e54d343ed7e6ffaf7e650525685934403006ad1428d2c9d0869b67b1920bea6

Test 5:
Data:    af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
Parity:  cedfc1cc789afb176bf1fb71a6756a5b315bdbc2322f987ff3aa7b0c7c2a6a7d

#### A.3.2 - Minimal Python Implementation

Using Python 3, numpy and galois:

1. Import the libraries:
    ```python
    import galois
    import numpy as np
    ```

2. Create the field with exact primitive polynomial:
   ```python
   GF = galois.GF(2**8, irreducible_poly=0x11d)
   ```

3. Verify primitive element is 2:
   ```python
   alpha = GF.primitive_element
   assert alpha == 2
   ```

4. Build generator polynomial manually:
   ```python
   g = galois.Poly([1], field=GF)
   x = galois.Poly([1, 0], field=GF)
   for i in range(1, 33): # α^1 through α^32
       g = g * (x - alpha**i)
   ```

5. Encode 32-byte data with systematic Reed-Solomon:
   ```python

    def rs_encode(data_bytes):
        """Encode 32-byte data with Reed-Solomon protection."""
        # Convert bytes to list for galois library
        data_list = list(data_bytes)
        data_gf = GF(data_list)
        data_poly = galois.Poly(data_gf[::-1], field=GF)
        shifted = data_poly * galois.Poly([1] + [0]*32, field=GF)
        _, remainder = divmod(shifted, g)
        parity_coeffs = remainder.coeffs[::-1] if remainder.degree >= 0 else []
        parity = np.zeros(32, dtype=np.uint8)
        parity[:len(parity_coeffs)] = [int(x) for x in parity_coeffs]
        return bytes(data_bytes) + bytes(parity)  # [data || parity]
   ```

Note: Do NOT use galois.ReedSolomon(64, 32) as it expects primitive codes.

## Appendix B: Reference Implementation

A reference implementation in Rust is available at https://github.com/hasenbanck/slz.

## Appendix C: Recommended File Extension

Files using this format SHOULD use the extension `.slz`.

## Revision History

- Version 0.4 (2025-08-17): Added block trailers with chaining values and Reed-Solomon protection
- Version 0.3 (2025-08-15): Initial specification
