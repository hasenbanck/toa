# TOA Compression File Format

This project implements the **TOA compression file format**, an experimental compression format
designed for streaming operation, parallel processing and corruption resilience. The format uses LZMA as the primary
compression algorithm with BLAKE3 cryptographic hashing and Reed-Solomon error correction codes.

**Note: The TOA format is currently in draft mode (v0.7) and not yet frozen. The specification may change in future
versions.**

## Installation and Usage

### Install via Cargo

```bash
cargo install toa
```

### Building from Source

```bash
git clone <repository-url>
cd toa
cargo build --release
```

### Compression

```bash
# Compress a file
toa input.txt
# Creates input.txt.toa
```

### Decompression

```bash
# Decompress a file
toa --decompress input.txt.toa
# Creates input.txt
```

### Advanced Usage

```bash
# Set compression level (0-9, default 6)
toa -9 input.txt
toa --preset 9 input.txt
toa --best input.txt

# Set block size for parallelization (2^^26 = 64 MiB)
toa -6 --block-size=26 input.txt

# List metadata and block information
toa --list input.txt.toa

# Specify output file
toa -o output.toa input.txt
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
