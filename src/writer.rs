//! Implementation of the single-threaded encoder.

use alloc::vec::Vec;
use core::num::NonZeroU64;

use crate::{ByteWriter, Result, Write, reed_solomon::encode};

const SLZ_MAGIC: [u8; 4] = [0xFE, 0xDC, 0xBA, 0x98];
const SLZ_VERSION: u8 = 0x01;

const TRAILER_SIZE: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    LZMA = 0x00,
    LZMA2 = 0x01,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefilter {
    None = 0x00,
    Delta = 0x01,
    BcjX86 = 0x02,
    BcjArm = 0x03,
    BcjArmThumb = 0x04,
    BcjArm64 = 0x05,
    BcjSparc = 0x06,
    BcjPowerPc = 0x07,
    BcjIa64 = 0x08,
    BcjRiscV = 0x09,
}

/// Options for SLZ compression.
#[derive(Debug, Clone)]
pub struct SLZOptions {
    /// Compression algorithm to use.
    pub algorithm: CompressionAlgorithm,
    /// Prefilter to apply before compression.
    pub prefilter: Prefilter,
    /// Dictionary size as power of 2 (12-32, representing 4KB to 4GB).
    pub dict_size_log2: u8,
    /// LZMA literal context bits (0-8).
    pub lc: u8,
    /// LZMA literal position bits (0-4).
    pub lp: u8,
    /// LZMA position bits (0-4).
    pub pb: u8,
    /// Delta filter distance (1-256) - only used if prefilter is Delta.
    pub delta_distance: u8,
    /// Block size in bytes. If None, all data is written as a single block.
    pub block_size: Option<NonZeroU64>,
}

impl Default for SLZOptions {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::LZMA2,
            prefilter: Prefilter::None,
            dict_size_log2: 23, // 8MB
            lc: 3,
            lp: 0,
            pb: 2,
            delta_distance: 1,
            block_size: None,
        }
    }
}

impl SLZOptions {
    /// Create options with a specific preset level (0-9).
    pub fn with_preset(level: u32) -> Self {
        let mut options = Self::default();
        match level {
            0..=1 => {
                options.dict_size_log2 = 16; // 64KB
            }
            2..=3 => {
                options.dict_size_log2 = 20; // 1MB
            }
            4..=5 => {
                options.dict_size_log2 = 22; // 4MB
            }
            6..=7 => {
                options.dict_size_log2 = 24; // 16MB
            }
            8..=9 => {
                options.dict_size_log2 = 26; // 64MB
            }
            _ => {
                options.dict_size_log2 = 23; // 8MB (default)
            }
        }
        options
    }

    /// Set the block size for multi-block compression.
    pub fn set_block_size(&mut self, block_size: Option<NonZeroU64>) {
        self.block_size = block_size;
    }

    /// Get dictionary size in bytes.
    pub fn dict_size(&self) -> u32 {
        if self.dict_size_log2 > 32 {
            return u32::MAX;
        }
        1u32 << self.dict_size_log2
    }

    /// Validate options and return error if invalid.
    pub fn validate(&self) -> Result<()> {
        if self.dict_size_log2 < 12 || self.dict_size_log2 > 32 {
            return Err(crate::error_invalid_input(
                "dictionary size must be between 2^12 and 2^32",
            ));
        }
        if self.lc > 8 {
            return Err(crate::error_invalid_input("lc must be <= 8"));
        }
        if self.lp > 4 {
            return Err(crate::error_invalid_input("lp must be <= 4"));
        }
        if self.pb > 4 {
            return Err(crate::error_invalid_input("pb must be <= 4"));
        }
        if self.delta_distance == 0 {
            return Err(crate::error_invalid_input("delta distance must be >= 1"));
        }
        Ok(())
    }
}

struct CountingWriter<W> {
    inner: W,
    bytes_written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let bytes_written = self.inner.write(buf)?;
        self.bytes_written += bytes_written as u64;
        Ok(bytes_written)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

/// A single-threaded SLZ compressor.
pub struct SLZWriter<W: Write> {
    inner: Option<W>,
    options: SLZOptions,
    header_written: bool,
    finished: bool,
    hasher: blake3::Hasher,
    uncompressed_size: u64,
    compressed_size: u64,
    current_block_data: Vec<u8>,
}

impl<W: Write> SLZWriter<W> {
    /// Create a new SLZ writer with the given options.
    pub fn new(inner: W, options: SLZOptions) -> Result<Self> {
        options.validate()?;

        Ok(Self {
            inner: Some(inner),
            options,
            header_written: false,
            finished: false,
            hasher: blake3::Hasher::new(),
            uncompressed_size: 0,
            compressed_size: 0,
            current_block_data: Vec::new(),
        })
    }

    /// Consume the writer and return the inner writer.
    pub fn into_inner(mut self) -> W {
        self.inner.take().expect("inner writer not set")
    }

    /// Check if we should finish the current block and start a new one.
    fn should_finish_block(&self) -> bool {
        if let Some(block_size) = self.options.block_size {
            self.current_block_data.len() as u64 >= block_size.get()
        } else {
            false
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

        // Configuration byte
        let config = (self.options.prefilter as u8) << 3 | (self.options.algorithm as u8);
        writer.write_u8(config)?;

        // Compression properties
        match self.options.algorithm {
            CompressionAlgorithm::LZMA => {
                // LZMA properties byte: (pb * 5 + lp) * 9 + lc
                let props = (self.options.pb * 5 + self.options.lp) * 9 + self.options.lc;
                writer.write_u8(props)?;
                // Dictionary size log2 minus 12
                writer.write_u8(self.options.dict_size_log2 - 12)?;
            }
            CompressionAlgorithm::LZMA2 => {
                // Dictionary size log2 minus 12
                writer.write_u8(self.options.dict_size_log2 - 12)?;
            }
        }

        // Prefilter properties
        match self.options.prefilter {
            Prefilter::Delta => {
                writer.write_u8(self.options.delta_distance - 1)?;
            }
            _ => {}
        }

        self.header_written = true;
        Ok(())
    }

    /// Compress and write a block of data.
    fn write_block(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Apply prefilter if needed
        let filtered_data = self.apply_prefilter(data)?;

        // Compress the data
        let compressed_data = self.compress_data(&filtered_data)?;

        // Write block size and data
        let writer = self.inner.as_mut().expect("inner writer not set");
        let block_size = compressed_data.len() as u32;
        writer.write_u32(block_size)?;
        writer.write_all(&compressed_data)?;

        self.compressed_size += compressed_data.len() as u64;

        Ok(())
    }

    /// Apply prefilter to data.
    fn apply_prefilter(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.options.prefilter {
            Prefilter::None => Ok(data.to_vec()),
            Prefilter::Delta => {
                let mut filtered = data.to_vec();
                let distance = self.options.delta_distance as usize;

                for i in distance..filtered.len() {
                    filtered[i] = filtered[i].wrapping_sub(filtered[i - distance]);
                }

                Ok(filtered)
            }
            _ => {
                // BCJ filters would be implemented here
                // For now, just return the data unchanged
                Ok(data.to_vec())
            }
        }
    }

    /// Compress data using the configured algorithm.
    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.options.algorithm {
            CompressionAlgorithm::LZMA => self.compress_lzma(data),
            CompressionAlgorithm::LZMA2 => self.compress_lzma2(data),
        }
    }

    /// Compress data using LZMA.
    fn compress_lzma(&self, data: &[u8]) -> Result<Vec<u8>> {
        use lzma_rust2::{LZMAOptions, LZMAWriter};

        let mut lzma_options = LZMAOptions::default();
        lzma_options.dict_size = self.options.dict_size();
        lzma_options.lc = self.options.lc as u32;
        lzma_options.lp = self.options.lp as u32;
        lzma_options.pb = self.options.pb as u32;

        let mut compressed = Vec::new();
        {
            let mut writer = LZMAWriter::new_no_header(&mut compressed, &lzma_options, false)
                .map_err(|_| crate::error_other("failed to create LZMA writer"))?;

            writer
                .write_all(data)
                .map_err(|_| crate::error_other("failed to write LZMA data"))?;

            writer
                .finish()
                .map_err(|_| crate::error_other("failed to finish LZMA compression"))?;
        }

        Ok(compressed)
    }

    /// Compress data using LZMA2.
    fn compress_lzma2(&self, data: &[u8]) -> Result<Vec<u8>> {
        use lzma_rust2::{LZMA2Options, LZMA2Writer};

        let mut lzma2_options = LZMA2Options::default();
        lzma2_options.lzma_options.dict_size = self.options.dict_size();

        let mut compressed = Vec::new();
        {
            let mut writer = LZMA2Writer::new(&mut compressed, lzma2_options);

            writer
                .write_all(data)
                .map_err(|_| crate::error_other("failed to write LZMA2 data"))?;

            writer
                .finish()
                .map_err(|_| crate::error_other("failed to finish LZMA2 compression"))?;
        }

        Ok(compressed)
    }

    /// Write the trailer with Blake3 hash and Reed-Solomon protection.
    fn write_trailer(&mut self) -> Result<()> {
        let writer = self.inner.as_mut().expect("inner writer not set");

        // Write end-of-blocks marker
        writer.write_u32(0)?;

        // Write size fields
        writer.write_u64(self.uncompressed_size)?;
        writer.write_u64(self.compressed_size)?;

        // Finalize Blake3 hash
        let hash = self.hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Generate Reed-Solomon parity
        let parity = encode(hash_bytes);

        // Write Blake3 hash
        writer.write_all(hash_bytes)?;

        // Write Reed-Solomon parity
        writer.write_all(&parity)?;

        Ok(())
    }

    /// Finish writing the SLZ stream.
    pub fn finish(mut self) -> Result<W> {
        if self.finished {
            return Ok(self.into_inner());
        }

        if !self.header_written {
            self.write_header()?;
        }

        // Write any remaining data in the current block
        if !self.current_block_data.is_empty() {
            let data = core::mem::take(&mut self.current_block_data);
            self.write_block(&data)?;
        }

        // Write trailer
        self.write_trailer()?;

        self.finished = true;
        Ok(self.into_inner())
    }
}

impl<W: Write> Write for SLZWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.finished {
            return Err(crate::error_invalid_input("SLZ writer already finished"));
        }

        if buf.is_empty() {
            return Ok(0);
        }

        if !self.header_written {
            self.write_header()?;
        }

        // Update hash with the uncompressed data
        self.hasher.update(buf);
        self.uncompressed_size += buf.len() as u64;

        let mut remaining = buf;
        let mut total_written = 0;

        while !remaining.is_empty() {
            if self.should_finish_block() && !self.current_block_data.is_empty() {
                // Finish current block
                let data = core::mem::take(&mut self.current_block_data);
                self.write_block(&data)?;
            }

            // Determine how much to add to current block
            let bytes_to_add = if let Some(block_size) = self.options.block_size {
                let space_in_block = block_size.get() - self.current_block_data.len() as u64;
                (remaining.len() as u64).min(space_in_block) as usize
            } else {
                remaining.len()
            };

            if bytes_to_add == 0 {
                // Block is full, finish it
                let data = core::mem::take(&mut self.current_block_data);
                self.write_block(&data)?;
                continue;
            }

            // Add data to current block
            self.current_block_data
                .extend_from_slice(&remaining[..bytes_to_add]);
            total_written += bytes_to_add;
            remaining = &remaining[bytes_to_add..];
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
