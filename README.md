# Streaming-LZMA (SLZ) Compression

Implementation of an experimental compression file format using LZMA optimized for streaming and parallel processing.

**Note: The SLZ format is currently in draft mode (v0.4) and not yet frozen. The specification may change in future
versions.**

## Overview

SLZ (Streaming-LZMA) is designed for scenarios where other compression formats fall short. The format provides:

- **Streaming operation**: Read data sequentially without seeks, random access or buffering (writing needs buffering)
- **Parallel processing**: Independent blocks enable concurrent compression and decompression for improved performance
- **Efficient append operations**: O(n) complexity where n is the number of blocks, not the data size, thanks to BLAKE3
  chaining values
- **Per-block validation**: Each block has its own integrity verification with Reed-Solomon error correction
- **High robustness**: Five-layer integrity protection from LZMA stream validation to cryptographic hashing

## Installation and Usage

### Install via Cargo

```bash
cargo install slz
```

### Building from Source

```bash
git clone <repository-url>
cd slz
cargo build --release
```

### Compression

```bash
# Compress a file
slz input.txt
# Creates input.txt.slz
```

### Decompression

```bash
# Decompress a file
slz --decompress input.txt.slz
# Creates input.txt
```

### Advanced Usage

```bash
# Set compression level (0-9, default 6)
slz -9 input.txt
slz --preset 9 input.txt
slz --best input.txt

# Set block size for parallelization (2^^26 = 64 MiB)
slz -6 --block-size=26 input.txt

# List metadata and block information
slz --list input.txt.slz

# Specify output file
slz -o output.slz input.txt
```

## Technical Details

Please have a look at the [specification](SPECIFICATION.md) for in depth details.

## Acknowledgement

- The lzma code is a hard copy of the lzma-rust crate (Apache 2 license).
- Original Author of the lzma-rust crate was dyz1990 (Apache 2 license)
- The lzma-rust2 crate was a rewrite of the XZ for Java by Lasse Collin (0BSD).
- Major parts of XZ for Java are based on code written by Igor Pavlov in the LZMA SDK (public domain).

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
