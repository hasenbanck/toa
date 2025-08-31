# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 - 2025-08-31

## Changes

- Freeze of the specification version 1.0
- Breaking chang: Use different polynomial for Reed-Solomon ECC. Switched from 0x11D (x^8 + x^4 + x^3 + x^2 + 1) to
  0x11B (x^8 + x^4 + x^3 + x + 1). This is the polynomial used by AES-GCM and is used by the GFNI
  x86_64 instruction set. This enables us to provide highly optimized RS ECC implementations.
- Provide SIMD implementation for the ECC encoder and decoder. This resulted in a speed-up of 10-15x for the ECC
  encoding and validation when decoding.

## Fixes

- Fixed delta encoding bug of uncompressed chunks, where the direction was wrong on the encoder side (encoding "more"
  with - instead of +).

## Added

- `SimdOverride` can be used to override the usage of SIMD in the error correction code.

## 0.2.1 - 2025-08-23

## Fixes

- Not functional updates. Only update Cargo.toml to fix docs.rs builds.
