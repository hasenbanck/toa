# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 - 2025-xx-xx

## Changes

- Breaking chang: Use different polynomial for Reed-Solomon ECC. Switched from 0x11D (x^8 + x^4 + x^3 + x^2 + 1) to
  0x11B (x^8 + x^4 + x^3 + x + 1). This is the polynomial used by AES-GCM and is used by the GFNI
  x86_64 instruction set. This enables us to provide highly optimized RS ECC implementations.

## 0.2.0 - 2025-08-23

## Updates

- First usable release that supports both multi-threaded compression and decompression.
- Renaming of ECC level. Set "Standard" as the default.
- Add "test" command

## 0.1.0 - 2025-08-21

### Added

- Initial release
