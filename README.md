# TOA - Modern Compression with Built-in Error Correction

[![Crate](https://img.shields.io/crates/v/toa.svg)](https://crates.io/crates/toa)

**TOA** is a next-generation compression format that combines **exceptional compression ratios** with **built-in error
correction**, **streaming operation**, and **parallel processing**. TOA provides unique resilience against data
corruption while maintaining competitive compression performance. Especially useful to guard important archival data
against bit rot. It uses LZMA2s, a special variant of LZMA as it's compression algorithm.

## Key Features

- **Excellent Compression**: Matches XZ compression ratios and beats gzip and zstd (uses LZMA internally)
- **Built-in Error Correction**: Reed-Solomon codes protect against data corruption
- **Cryptographic Integrity**: BLAKE3 hashing for tamper detection
- **Streaming & Parallel**: Process data as it arrives with multi-core support
- **Executable Optimization**: Optional BCJ filters for better executable compression

## ⚠ Specification Status ⚠

**TOA is still experimental, do NOT use it in production yet**

**Note**: TOA format is currently at specification version 0.10 and not yet frozen. While the core features are stable,
the format may evolve before reaching version 1.0. The specification is thoroughly documented
in [SPECIFICATION.md](SPECIFICATION.md).

## Compression Performance

Benchmark results for `toa.exe` (903K original):

| Format                 | Size | Compression | Notes                                     |
|------------------------|------|-------------|-------------------------------------------|
| **TOA (extreme ECC)**  | 392K | 56.6%       | Extreme error correction                  |
| **TOA (paranoid ECC)** | 336K | 62.8%       | Paranoid error correction                 |
| **TOA (standard ECC)** | 314K | 65.2%       | Standard error correction                 |
| **TOA (no ECC)**       | 294K | 67.4%       | Best compression, only metadata protected |
| XZ                     | 294K | 67.4%       | Reference compression                     |
| zstd -9                | 356K | 60.6%       | Modern compression                        |
| zstd -3                | 377K | 58.3%       | Fast compression                          |
| gzip -9                | 367K | 59.4%       | Traditional compression                   |

**TOA delivers XZ-level compression with unique, built-in error correction capabilities that no other format provides.**

## Installation

### Install Pre-built Binary

Download the latest release from [GitHub Releases](https://github.com/hasenbanck/toa/releases)

### Install via Cargo

```bash
cargo install toa
```

### Build from Source

```bash
git clone https://github.com/hasenbanck/toa
cd toa
cargo build --release
```

## Quick Start

### Basic Compression

```bash
# Compress a file (uses optimal preset 6)
toa input.txt
# → Creates input.txt.toa

# Compress with no error correction for the data
toa --ecc none input.txt
```

### Decompression

```bash
# Decompress a file
toa -d input.txt.toa
# → Restores input.txt

# Keep original file during decompression
toa -dk input.txt.toa
```

### File Information

```bash
# View file metadata and block information
toa -l archive.toa
```

## Advanced Usage

### Compression Presets

```bash
# Ultra-fast compression (preset 0)
toa -0 input.txt

# Default balanced compression (preset 6)
toa input.txt

# Maximum compression for large files (preset 9)
toa -9 largefile.bin
```

### Error Correction Levels

Use Standard unless you have a specific reason not to. It handles all normal storage degradation for decades. Paranoid
and Extreme are for specialized scenarios like single-copy archives on sketchy media or century-scale preservation.

```bash
# Standard ECC: 6.3% overhead, corrects 8 bytes per 255-byte block (default)
toa --ecc standard input.txt

# Paranoid ECC: 12.5% overhead, corrects 16 bytes per 255-byte block  
toa --ecc paranoid input.txt

# Extreme ECC: 25% overhead, corrects 32 bytes per 255-byte block
toa --ecc extreme input.txt

# No ECC: Only metadata is protected
toa --ecc none input.txt
```

### Executable Compression with BCJ Filters

```bash
# Optimize x86 executables
toa --x86 program.exe

# Optimize ARM binaries
toa --arm64 arm-binary
```

### Parallel Processing

```bash
# Use all CPU cores (default)
toa -9 --threads 0 largefile.bin

# Specify thread count
toa --threads 8 input.txt

# Optimize block count for parallelization
toa --block-count 32 input.txt
```

### Custom Compression Settings

```bash
# Fine-tune LZMA parameters
toa --lc 3 --lp 0 --pb 2 --dict-size 26 input.txt

# Specify exact output file
toa -o compressed.toa input.txt
```

### Compression Verification

```bash
# Compress with verification to ensure data integrity
toa --verify important-data.txt

# Combine with keep flag for extra safety
toa --verify --keep backup.tar

# Verify with verbose output
toa --verify --verbose database.sql
```

## When to Use TOA

### Perfect for:

- **Long-term archival** - Built-in error correction prevents data loss
- **Network transmission** - Streaming decompression with corruption recovery
- **Distributed systems** - Cryptographic integrity verification
- **Large files** - Parallel processing scales with available cores
- **Executables** - BCJ filters provide superior compression

### Consider alternatives for:

- **Real-time applications** - Use faster formats like LZ4 or zstd-fast
- **Legacy compatibility** - Use established formats where required

## Technical Overview

TOA combines proven technologies in a novel way:

- **LZMA2s compression**: Simplified variant of LZMA2 for better worst-case handling than LZMA
- **BLAKE3 tree hashing**: Parallel cryptographic verification with 256-bit security
- **Reed-Solomon error correction**: Multi-layer protection against corruption
- **Streaming architecture**: Process data without seeking or buffering
- **Block independence**: Each block can be verified and recovered separately

## Roadmap

- Repair command
    - Single file: Use ECC to repair file
    - Multiple files: Use different, potentially corrupted version of a file (for example from different media) and
      try to repair both of them by using incremental repair routines.
- Extending the libtoa (Rust) library to support more use-cases
- Add a C interface and provide static / dynamic libraries to link against (for natively supporting more languages)

## Acknowledgement

- The lzma code is a hard copy of the lzma-rust crate (Apache 2 license).
- Original Author of the lzma-rust crate was dyz1990 (Apache 2 license)
- The lzma-rust2 crate was a rewrite of the XZ for Java by Lasse Collin (0BSD).
- Major parts of XZ for Java are based on code written by Igor Pavlov in the LZMA SDK (public domain).

## License

Licensed under the [Apache License, Version 2.0](LICENSE)

The TOA specification is placed in the public domain for unrestricted implementation.
