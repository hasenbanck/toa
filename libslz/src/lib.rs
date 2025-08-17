//! # Streaming-LZMA (SLZ) Compression
//!
//! Implementation of an experimental compression file format using LZMA optimized for streaming and parallel processing.
//!
//! **Note: The SLZ format is currently in draft mode (v0.3) and not yet frozen. The specification may change in future
//! versions.**
//!
//! ## Overview
//!
//! SLZ (Streaming-LZMA) is designed for scenarios where traditional compression formats fall short. The format provides:
//!
//! - **Streaming operation**: Read data sequentially without seeks, random access or buffering (Writing needs buffering)
//! - **Parallel processing**: Independent blocks enable concurrent decompression for improved performance
//! - **Data integrity**: Blake3 hashing which is protected by error correction (Reed-Solomon)
//!
//! SLZ main selling point is its easily parallelization, especially when decompressing, and it's strong data protection by
//! an innovative usage of a strong cryptographic hash function (blake3) and the elimination of false positives in the form
//! of error correcting the content hash with the help of a Reed-Solomon error correction.
//!
//! ## Acknowledgement
//!
//! - The lzma code is a hard copy of the lzma-rust crate (Apache 2 license).
//! - Original Author of the lzma-rust crate was dyz1990 (Apache 2 license)
//! - The lzma-rust2 crate was a rewrite of the XZ for Java by Lasse Collin (0BSD).
//! - Major parts of XZ for Java are based on code written by Igor Pavlov in the LZMA SDK (public domain).
//!
//! ## License
//!
//! Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
#![forbid(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod lzma;
mod reader;
pub mod reed_solomon;

mod writer;

mod header;
mod metadata;
#[cfg(not(feature = "std"))]
mod no_std;
mod trailer;

#[cfg(feature = "std")]
pub(crate) use std::io::Error;
#[cfg(feature = "std")]
pub(crate) use std::io::Read;
#[cfg(feature = "std")]
pub(crate) use std::io::Write;

use blake3::hazmat::{ChainingValue, Mode};
use header::SLZHeader;
pub use lzma::optimized_reader;
pub use metadata::SLZMetadata;
#[cfg(not(feature = "std"))]
pub use no_std::Error;
#[cfg(not(feature = "std"))]
pub use no_std::Read;
#[cfg(not(feature = "std"))]
pub use no_std::Write;
pub use reader::SLZStreamingReader;
use trailer::SLZTrailer;
pub use writer::{SLZOptions, SLZStreamingWriter};

/// Result type of the crate.
#[cfg(feature = "std")]
pub type Result<T> = core::result::Result<T, Error>;

/// Result type of the crate.
#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, Error>;

const SLZ_MAGIC: [u8; 4] = [0xFE, 0xDC, 0xBA, 0x98];

const SLZ_VERSION: u8 = 0x01;

/// Prefilter types that can be applied before LZMA compression to improve compression ratios
/// for specific data types like executable files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefilter {
    /// No prefilter
    None,
    /// Delta filter
    Delta {
        /// Filter distance (must be 1..=256)
        distance: u16,
    },
    /// BCJ filter for x86 (32-bit and 64-bit) executables
    BcjX86,
    /// BCJ filter for ARM executables
    BcjArm,
    /// BCJ filter for ARM Thumb executables
    BcjArmThumb,
    /// BCJ filter for ARM64 executables
    BcjArm64,
    /// BCJ filter for SPARC executables
    BcjSparc,
    /// BCJ filter for PowerPC executables
    BcjPowerPc,
    /// BCJ filter for IA-64 executables
    BcjIa64,
    /// BCJ filter for RISC-V executables
    BcjRiscV,
}

impl From<Prefilter> for u8 {
    fn from(value: Prefilter) -> Self {
        match value {
            Prefilter::None => 0x00,
            Prefilter::Delta { .. } => 0x01,
            Prefilter::BcjX86 => 0x02,
            Prefilter::BcjArm => 0x03,
            Prefilter::BcjArmThumb => 0x04,
            Prefilter::BcjArm64 => 0x05,
            Prefilter::BcjSparc => 0x06,
            Prefilter::BcjPowerPc => 0x07,
            Prefilter::BcjIa64 => 0x08,
            Prefilter::BcjRiscV => 0x09,
        }
    }
}

trait ByteReader {
    fn read_u8(&mut self) -> Result<u8>;

    fn read_u64(&mut self) -> Result<u64>;
}

trait ByteWriter {
    fn write_u8(&mut self, value: u8) -> Result<()>;

    fn write_u64(&mut self, value: u64) -> Result<()>;
}

impl<T: Read> ByteReader for T {
    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[inline(always)]
    fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(buf.as_mut())?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl<T: Write> ByteWriter for T {
    #[inline(always)]
    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write_all(&[value])
    }

    #[inline(always)]
    fn write_u64(&mut self, value: u64) -> Result<()> {
        self.write_all(&value.to_le_bytes())
    }
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_eof() -> Error {
    Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_other(msg: &'static str) -> Error {
    Error::other(msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_invalid_input(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::InvalidInput, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_invalid_data(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::InvalidData, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_unsupported(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::Unsupported, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn copy_error(error: &Error) -> Error {
    Error::new(error.kind(), error.to_string())
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_eof() -> Error {
    Error::EOF
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_other(msg: &'static str) -> Error {
    Error::Other(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_invalid_input(msg: &'static str) -> Error {
    Error::InvalidInput(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_invalid_data(msg: &'static str) -> Error {
    Error::InvalidData(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_out_of_memory(msg: &'static str) -> Error {
    Error::OutOfMemory(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_unsupported(msg: &'static str) -> Error {
    Error::Unsupported(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn copy_error(error: &Error) -> Error {
    *error
}

fn resolve_cv_stack(mut cv_stack: Vec<ChainingValue>) -> Result<[u8; 32]> {
    // TODO Verify that all CVs except the last one are of the same size and also a power of two.
    //      If this is not the case, we have a invalid stream.

    while cv_stack.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in cv_stack.chunks(2) {
            if chunk.len() == 2 {
                // Merge two chaining values - use root merging for the final level.
                let is_root = cv_stack.len() == 2;
                let mode = Mode::Hash;
                let merged = if is_root {
                    blake3::hazmat::merge_subtrees_root(&chunk[0], &chunk[1], mode).into()
                } else {
                    blake3::hazmat::merge_subtrees_non_root(&chunk[0], &chunk[1], mode)
                };
                next_level.push(merged);
            } else {
                // Odd number - promote the last one.
                next_level.push(chunk[0]);
            }
        }

        cv_stack = next_level;
    }

    Ok(cv_stack[0])
}
