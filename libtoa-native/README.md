# libtoa-c - C Library Interface for TOA Compression

This crate provides a C-compatible interface for the TOA compression library.

Currently, it only provides a buffer based API that uses the single-threaded encoder/decoder. This is still a draft and
very much work-in progress.

## Building

### Build the Library

Build the static and dynamic libraries:

```bash
cargo build --release
```

## Thread Safety

The TOA C library functions are thread-safe. Multiple threads can call compression and decompression functions
concurrently without external synchronization.

## Acknowledgement

- The lzma code is a hard copy of the lzma-rust crate (Apache 2 license).
- Original Author of the lzma-rust crate was dyz1990 (Apache 2 license)
- The lzma-rust2 crate was a rewrite of the XZ for Java by Lasse Collin (0BSD).
- Major parts of XZ for Java are based on code written by Igor Pavlov in the LZMA SDK (public domain).

## License

Licensed under the [Apache License, Version 2.0](../LICENSE)
