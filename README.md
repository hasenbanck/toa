# Streaming-LZMA (SLZ) Compression

Implementation of an experimental compression file format using LZMA optimized for streaming and parallel processing.

**Note: The SLZ format is currently in draft mode (v0.3) and not yet frozen. The specification may change in future
versions.**

## Overview

SLZ (Streaming-LZMA) is designed for scenarios where traditional compression formats fall short. The format provides:

- **Streaming operation**: Read data sequentially without seeks, random access or buffering (Writing needs buffering)
- **Parallel processing**: Independent blocks enable concurrent decompression for improved performance
- **Data integrity**: Blake3 hashing which is protected by error correction (Reed-Solomon)

SLZ main selling point is its easily parallelization, especially when decompressing, and it's strong data protection by
an innovative usage of a strong cryptographic hash function (blake3) and the elimination of false positives in the form
of error correcting the content hash with the help of a Reed-Solomon error correction.

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

# Set block count for parallelization
slz -6 --block-count=64 input.txt

# List metadata 
slz --list input.txt.slz

# Specify output file
slz -o output.slz input.txt
```

## Acknowledgement

- The lzma code is a hard copy of the lzma-rust crate (Apache 2 license).
- Original Author of the lzma-rust crate was dyz1990 (Apache 2 license)
- The lzma-rust2 crate was a rewrite of the XZ for Java by Lasse Collin (0BSD).
- Major parts of XZ for Java are based on code written by Igor Pavlov in the LZMA SDK (public domain).

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
