//! Implementation of the single-threaded encoder.

use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};
use std::num::NonZeroU32;

use lzma_rust2::{
    LZMAOptions, LZMAWriter,
    filter::{bcj::BCJWriter, delta::DeltaWriter},
};

use crate::{ByteWriter, Result, Write, error_invalid_data, reed_solomon::encode};

const SLZ_MAGIC: [u8; 4] = [0xFE, 0xDC, 0xBA, 0x98];

const SLZ_VERSION: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefilter {
    /// No prefilter
    None,
    /// Delta filter
    Delta {
        /// Filter distance (must be 1..=256)
        distance: u16,
    },
    BcjX86,
    BcjArm,
    BcjArmThumb,
    BcjArm64,
    BcjSparc,
    BcjPowerPc,
    BcjIa64,
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

/// Options for SLZ compression.
#[derive(Debug, Clone, Copy)]
pub struct SLZOptions {
    /// Prefilter to apply before compression.
    prefilter: Prefilter,
    /// Dictionary size to use for the LZMA compression algorithm as a power of two.
    dictionary_size_log2: u8,
    /// LZMA literal context bits (0-8).
    lc: u8,
    /// LZMA literal position bits (0-4).
    lp: u8,
    /// LZMA position bits (0-4).
    pb: u8,
    /// Block size in bytes. If None, all data will be written in blocks of 4 GiB - 1 B;
    block_size: Option<NonZeroU32>,
}

impl Default for SLZOptions {
    fn default() -> Self {
        Self {
            prefilter: Prefilter::None,
            dictionary_size_log2: 26,
            lc: 3,
            lp: 0,
            pb: 2,
            block_size: None,
        }
    }
}

impl SLZOptions {
    const PRESET_TO_DICT_SIZE_LOG2: &'static [u8] = &[
        18, // 256 KiB
        20, // 1 MiB
        21, // 2 MiB
        22, // 4 MiB
        22, // 4 MiB
        23, // 8 MiB
        23, // 8 MiB
        24, // 16 MiB
        25, // 32 MiB
        26, // 64 MiB
    ];

    /// Create options with a specific preset level (0-9).
    pub fn from_preset(level: u32) -> Self {
        let level = level.min(9);

        let dictionary_size_log2 = Self::PRESET_TO_DICT_SIZE_LOG2[level as usize];
        let block_size = u32::MAX;

        Self {
            prefilter: Prefilter::None,
            dictionary_size_log2,
            lc: 3,
            lp: 0,
            pb: 2,
            block_size: NonZeroU32::new(block_size),
        }
    }

    /// Sets the LZMA literal context bits.
    ///
    /// Clamped in range of 0 and 8.
    pub fn with_lc(mut self, lc: u8) -> Self {
        self.lc = lc.clamp(0, 8);
        self
    }

    /// Sets the LZMA literal position bits.
    ///
    /// Clamped in range of 0 and 4.
    pub fn with_lp(mut self, lp: u8) -> Self {
        self.lp = lp.clamp(0, 4);
        self
    }

    /// Sets the LZMA position bits (0-4).
    ///
    /// Clamped in range of 0 and 4.
    pub fn with_pb(mut self, pb: u8) -> Self {
        self.pb = pb.clamp(0, 4);
        self
    }

    /// Set the prefilter to use.
    ///
    /// Delta filter distance will be clamped in range of 1 and 256.
    pub fn with_prefilter(mut self, prefilter: Prefilter) -> Self {
        let mut prefilter = prefilter;

        if let Prefilter::Delta { distance } = &mut prefilter {
            *distance = (*distance).clamp(1, 256);
        }

        self.prefilter = prefilter;
        self
    }

    /// Set the dictionary size of the LZMA compression algorithm.
    ///
    /// Clamped in range of 16 (64 KiB) and 32 (4 GiB).
    pub fn with_dictionary_size(mut self, dictionary_size_log2: u8) -> Self {
        self.dictionary_size_log2 = dictionary_size_log2.clamp(16, 32);
        self
    }

    /// Set the block size for multi-block compression.
    pub fn with_block_size(mut self, block_size: Option<NonZeroU32>) -> Self {
        self.block_size = block_size;
        self
    }

    /// Get dictionary size in bytes.
    pub fn dict_size(&self) -> u32 {
        2u32.pow(self.dictionary_size_log2 as u32)
    }
}

trait FinishableWriter: Write {
    fn finish(self: Box<Self>) -> Result<()>;
}

impl<W: Write> FinishableWriter for LZMAWriter<W> {
    fn finish(self: Box<Self>) -> Result<()> {
        (*self).finish()?;
        Ok(())
    }
}

impl<W: FinishableWriter> FinishableWriter for DeltaWriter<W> {
    fn finish(self: Box<Self>) -> Result<()> {
        let inner = (*self).into_inner();
        Box::new(inner).finish()
    }
}

impl<W: FinishableWriter> FinishableWriter for BCJWriter<W> {
    fn finish(self: Box<Self>) -> Result<()> {
        let inner = (*self).into_inner();
        Box::new(inner).finish()
    }
}

impl<'writer> FinishableWriter for Box<dyn FinishableWriter + 'writer> {
    fn finish(self: Box<Self>) -> Result<()> {
        (*self).finish()
    }
}

struct SharedWriter<W> {
    inner: Rc<RefCell<W>>,
    bytes_written: Rc<Cell<u64>>,
}

impl<W> SharedWriter<W> {
    fn new(inner: W, bytes_written: Rc<Cell<u64>>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(inner)),
            bytes_written,
        }
    }
}

impl<W: Write> Write for SharedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut writer = self.inner.borrow_mut();
        let bytes_written = writer.write(buf)?;
        self.bytes_written
            .set(self.bytes_written.get() + bytes_written as u64);
        Ok(bytes_written)
    }

    fn flush(&mut self) -> Result<()> {
        let mut writer = self.inner.borrow_mut();
        writer.flush()
    }
}

/// A single-threaded SLZ compressor.
pub struct SLZWriter<W> {
    inner: Option<W>,
    options: SLZOptions,
    header_written: bool,
    hasher: blake3::Hasher,
    uncompressed_size: u64,
    compressed_size: Rc<Cell<u64>>,
    current_block_data: Vec<u8>,
}

impl<W: Write> SLZWriter<W> {
    /// Create a new SLZ writer with the given options.
    pub fn new(inner: W, options: SLZOptions) -> Self {
        Self {
            inner: Some(inner),
            options,
            header_written: false,
            hasher: blake3::Hasher::new(),
            uncompressed_size: 0,
            compressed_size: Rc::new(Cell::new(0)),
            current_block_data: Vec::new(),
        }
    }

    /// Write the header.
    fn write_header(&mut self) -> Result<()> {
        if self.header_written {
            return Ok(());
        }

        let writer = self.inner.as_mut().expect("inner writer not set");

        // Magic bytes
        writer.write_all(&SLZ_MAGIC)?;

        // Version
        writer.write_u8(SLZ_VERSION)?;

        // Prefilter configuration byte
        let config = u8::from(self.options.prefilter);
        writer.write_u8(config)?;

        // LZMA properties byte: (pb * 5 + lp) * 9 + lc
        let props = (self.options.pb * 5 + self.options.lp) * 9 + self.options.lc;
        writer.write_u8(props)?;

        // Dictionary size: log2 minus 16
        writer.write_u8(self.options.dictionary_size_log2 - 16)?;

        // Prefilter properties
        if let Prefilter::Delta { distance } = self.options.prefilter {
            writer.write_u8(distance as u8 - 1)?;
        }

        self.header_written = true;

        Ok(())
    }

    /// Compress and write a block of data with size prepended.
    fn compress_and_write_block(&mut self) -> Result<()> {
        if self.current_block_data.is_empty() {
            return Ok(());
        }

        // Create a buffer to collect compressed data.
        let mut compressed_data = Vec::new();

        // Set up compression chain.
        let mut writer: Box<dyn FinishableWriter> = Box::new(LZMAWriter::new_no_header(
            SharedWriter::new(&mut compressed_data, Rc::clone(&self.compressed_size)),
            &LZMAOptions {
                dict_size: self.options.dict_size(),
                lc: u32::from(self.options.lc),
                lp: u32::from(self.options.lp),
                pb: u32::from(self.options.pb),
                ..Default::default()
            },
            false,
        )?);

        // Apply prefilter if configured
        match self.options.prefilter {
            Prefilter::None => {}
            Prefilter::Delta { distance } => {
                writer = Box::new(DeltaWriter::new(writer, distance as usize))
            }
            Prefilter::BcjX86 => writer = Box::new(BCJWriter::new_x86(writer, 0)),
            Prefilter::BcjArm => writer = Box::new(BCJWriter::new_arm(writer, 0)),
            Prefilter::BcjArmThumb => writer = Box::new(BCJWriter::new_arm_thumb(writer, 0)),
            Prefilter::BcjArm64 => writer = Box::new(BCJWriter::new_arm64(writer, 0)),
            Prefilter::BcjSparc => writer = Box::new(BCJWriter::new_sparc(writer, 0)),
            Prefilter::BcjPowerPc => writer = Box::new(BCJWriter::new_ppc(writer, 0)),
            Prefilter::BcjIa64 => writer = Box::new(BCJWriter::new_ia64(writer, 0)),
            Prefilter::BcjRiscV => writer = Box::new(BCJWriter::new_riscv(writer, 0)),
        }

        // Compress the data.
        writer.write_all(self.current_block_data.as_slice())?;
        writer.finish()?;

        let compressed_size = self.compressed_size.get();

        if compressed_size > u32::MAX as u64 {
            return Err(error_invalid_data("compressed block too large"));
        }

        // Write block size (4 bytes, little-endian).
        let inner_writer = self.inner.as_mut().expect("inner writer not set");
        inner_writer.write_u32(compressed_size as u32)?;

        // Write compressed data.
        inner_writer.write_all(&compressed_data)?;

        Ok(())
    }

    /// Write the trailer with Blake3 hash and Reed-Solomon protection.
    fn write_trailer(&mut self) -> Result<()> {
        let writer = self.inner.as_mut().expect("inner writer not set");

        // Write end-of-blocks marker.
        writer.write_u32(0)?;

        // Write size fields.
        writer.write_u64(self.uncompressed_size)?;
        writer.write_u64(self.compressed_size.get())?;

        // Finalize Blake3 hash.
        let hash = self.hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Generate Reed-Solomon parity.
        let parity = encode(hash_bytes);

        // Write Blake3 hash.
        writer.write_all(hash_bytes)?;

        // Write Reed-Solomon parity.
        writer.write_all(&parity)?;

        Ok(())
    }

    /// Consume the writer and return the inner writer.
    pub fn into_inner(mut self) -> W {
        self.inner.take().expect("inner writer not set")
    }

    /// Finish writing the SLZ stream.
    pub fn finish(mut self) -> Result<W> {
        if !self.header_written {
            self.write_header()?;
        }

        // Write any remaining data in the current block
        if !self.current_block_data.is_empty() {
            self.compress_and_write_block()?;
        }

        self.write_trailer()?;

        Ok(self.into_inner())
    }
}

impl<W: Write> Write for SLZWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.header_written {
            self.write_header()?;
        }

        let mut total_written = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // Calculate how much space is left in the current block
            let block_limit = if let Some(block_size) = self.options.block_size {
                block_size.get() as usize
            } else {
                u32::MAX as usize // Max block size is 4 GiB - 1
            };

            let space_left = block_limit.saturating_sub(self.current_block_data.len());

            if space_left == 0 {
                // Current block is full, compress and write it out
                self.compress_and_write_block()?;
                self.current_block_data.clear();
                continue;
            }

            // Take as much data as fits in the current block
            let to_write = remaining.len().min(space_left);
            let chunk = &remaining[..to_write];

            // Add to block buffer and update hash
            self.current_block_data.extend_from_slice(chunk);
            self.hasher.update(chunk);
            self.uncompressed_size += to_write as u64;

            total_written += to_write;
            remaining = &remaining[to_write..];
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(ref mut writer) = self.inner {
            writer.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_slz_writer_empty() {
        let mut buffer = Vec::new();

        let options = SLZOptions {
            prefilter: Prefilter::None,
            dictionary_size_log2: 16,
            lc: 3,
            lp: 0,
            pb: 2,
            block_size: None,
        };

        let writer = SLZWriter::new(Cursor::new(&mut buffer), options);
        let _ = writer.finish().unwrap();

        let expected_blake_hash: [u8; 32] =
            hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        let expected_rs_parity: [u8; 32] =
            hex!("cedfc1cc789afb176bf1fb71a6756a5b315bdbc2322f987ff3aa7b0c7c2a6a7d");

        // Total file size should be: 8 (header) + 4 (end marker) + 80 (trailer) = 92 bytes
        assert_eq!(buffer.len(), 92, "Total file size should be 92 bytes");

        let (header, rest) = buffer.split_at(8);
        let (blocks, trailer) = rest.split_at(4);

        // Magic bytes: 0xFE 0xDC 0xBA 0x98 (4 bytes)
        assert_eq!(header[0], 0xFE, "Magic byte 0");
        assert_eq!(header[1], 0xDC, "Magic byte 1");
        assert_eq!(header[2], 0xBA, "Magic byte 2");
        assert_eq!(header[3], 0x98, "Magic byte 3");

        // Version: 0x01 (1 byte)
        assert_eq!(header[4], 0x01, "Format version should be 1");

        // Configuration: No prefilter = 0x00 (1 byte)
        assert_eq!(header[5], 0x00, "Configuration: LZMA + no prefilter");

        // LZMA properties: 93 ( 2 (pb) * 5 + 0 (lp)) * 9 + 3 (lc)
        assert_eq!(header[6], 0x5D, "Configuration: LZMA + no prefilter");

        // LZMA dictionary size: 16 - 16 = 0 (1 byte)
        assert_eq!(header[7], 0x00, "LZMA dictionary size should be 0");

        // End-of-blocks marker: 0x00 0x00 0x00 0x00
        assert_eq!(blocks, &[0x00, 0x00, 0x00, 0x00], "End-of-blocks marker");

        assert_eq!(trailer.len(), 80, "Trailer should be exactly 80 bytes");

        // Uncompressed size: 0 (8 bytes, little-endian)
        assert_eq!(
            &trailer[0..8],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "Uncompressed size should be 0"
        );

        // Compressed size: 0 (8 bytes, little-endian)
        assert_eq!(
            &trailer[8..16],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "Compressed size should be 0"
        );

        // Blake3 hash of empty data (32 bytes)
        assert_eq!(&trailer[16..48], &expected_blake_hash, "Blake3 hash");

        // Reed-Solomon parity (32 bytes)
        assert_eq!(&trailer[48..80], &expected_rs_parity, "RS parity");

        hexdump::hexdump(&buffer);
    }
}
