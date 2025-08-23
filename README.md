# TOA - Modern Compression with Built-in Error Correction

**TOA** is a next-generation compression format that combines **exceptional compression ratios** with **built-in error
correction**, **streaming operation**, and **parallel processing**. TOA provides unique resilience against data
corruption while maintaining competitive compression performance.

## Key Features

- **Excellent Compression**: Matches XZ compression ratios and beats gzip and zstd
- **Built-in Error Correction**: Reed-Solomon codes protect against data corruption
- **Cryptographic Integrity**: BLAKE3 hashing for tamper detection
- **Streaming & Parallel**: Process data as it arrives with multi-core support
- **Executable Optimization**: Optional BCJ filters for better executable compression

## Specification Status

**Note**: TOA format is currently at specification version 0.8 and not yet frozen. While the core features are stable,
the format may evolve before reaching version 1.0. The specification is thoroughly documented
in [SPECIFICATION.md](SPECIFICATION.md).

## Compression Performance

Benchmark results for `toa.exe` (903K original):

| Format               | Size     | Compression | Notes                                         |
|----------------------|----------|-------------|-----------------------------------------------|
| **TOA (no ECC)**     | **294K** | **67.4%**   | Best compression, maximum resilience metadata |
| **XZ**               | **294K** | **67.4%**   | Reference compression                         |
| **TOA (light ECC)**  | **314K** | **65.2%**   | Light error correction                        |
| **TOA (medium ECC)** | **336K** | **62.8%**   | **Better than gz/zst with strong ECC**        |
| **TOA (heavy ECC)**  | **392K** | **56.6%**   | Maximum error correction                      |
| gzip -9              | 367K     | 59.4%       | Traditional compression                       |
| zstd -9              | 356K     | 60.6%       | Modern compression                            |
| zstd -3              | 377K     | 58.3%       | Fast compression                              |

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

# Compress with error correction
toa --ecc medium input.txt
# → Adds 6.3% overhead but can correct 8 bytes per 255-byte block
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

```bash
# Light ECC: 6.3% overhead, corrects 8 bytes per 255-byte block
toa --ecc light input.txt

# Medium ECC: 12.5% overhead, corrects 16 bytes per 255-byte block  
toa --ecc medium input.txt

# Heavy ECC: 25% overhead, corrects 32 bytes per 255-byte block
toa --ecc heavy input.txt
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

## Error Correction Demonstration

TOA's Reed-Solomon codes can recover from significant corruption:

```bash
# Create a file with medium error correction
toa --ecc medium important-data.txt

# Simulate corruption (up to 16 bytes per 255-byte block can be recovered)
# TOA can automatically detect and correct the corruption during decompression
toa -d important-data.txt.toa
```

## Acknowledgement

- The lzma code is a hard copy of the lzma-rust crate (Apache 2 license).
- Original Author of the lzma-rust crate was dyz1990 (Apache 2 license)
- The lzma-rust2 crate was a rewrite of the XZ for Java by Lasse Collin (0BSD).
- Major parts of XZ for Java are based on code written by Igor Pavlov in the LZMA SDK (public domain).

## License

Licensed under the [Apache License, Version 2.0](LICENSE)

The TOA specification is placed in the public domain for unrestricted implementation.
