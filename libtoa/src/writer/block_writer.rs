use alloc::vec::Vec;

use blake3::hazmat::HasherExt;

use crate::{
    Prefilter, Result, TOAOptions, Write, error_invalid_data,
    header::TOABlockHeader,
    lzma::{LZMA2sWriter, LZMAOptions, filter::bcj::BCJWriter},
    writer::ecc_writer::ECCWriter,
};

/// All possible writer combination for a single block.
#[allow(clippy::large_enum_variant)]
enum Writer {
    Lzma(LZMA2sWriter<ECCWriter<Vec<u8>>>),
    BcjX86(BCJWriter<LZMA2sWriter<ECCWriter<Vec<u8>>>>),
    BcjArm(BCJWriter<LZMA2sWriter<ECCWriter<Vec<u8>>>>),
    BcjArmThumb(BCJWriter<LZMA2sWriter<ECCWriter<Vec<u8>>>>),
    BcjArm64(BCJWriter<LZMA2sWriter<ECCWriter<Vec<u8>>>>),
    BcjSparc(BCJWriter<LZMA2sWriter<ECCWriter<Vec<u8>>>>),
    BcjPowerPc(BCJWriter<LZMA2sWriter<ECCWriter<Vec<u8>>>>),
    BcjIa64(BCJWriter<LZMA2sWriter<ECCWriter<Vec<u8>>>>),
    BcjRiscV(BCJWriter<LZMA2sWriter<ECCWriter<Vec<u8>>>>),
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            Writer::Lzma(writer) => writer.write(buf),
            Writer::BcjX86(writer) => writer.write(buf),
            Writer::BcjArm(writer) => writer.write(buf),
            Writer::BcjArmThumb(writer) => writer.write(buf),
            Writer::BcjArm64(writer) => writer.write(buf),
            Writer::BcjSparc(writer) => writer.write(buf),
            Writer::BcjPowerPc(writer) => writer.write(buf),
            Writer::BcjIa64(writer) => writer.write(buf),
            Writer::BcjRiscV(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            Writer::Lzma(writer) => writer.flush(),
            Writer::BcjX86(writer) => writer.flush(),
            Writer::BcjArm(writer) => writer.flush(),
            Writer::BcjArmThumb(writer) => writer.flush(),
            Writer::BcjArm64(writer) => writer.flush(),
            Writer::BcjSparc(writer) => writer.flush(),
            Writer::BcjPowerPc(writer) => writer.flush(),
            Writer::BcjIa64(writer) => writer.flush(),
            Writer::BcjRiscV(writer) => writer.flush(),
        }
    }
}

impl Writer {
    /// Create a new writer chain based on the options.
    fn new(options: &TOAOptions, block_size: u64, buffer: Vec<u8>) -> Self {
        let ecc_writer = ECCWriter::new(buffer, options.error_correction);

        let lzma_writer = LZMA2sWriter::new(
            ecc_writer,
            block_size,
            &LZMAOptions {
                dict_size: options.dict_size(),
                lc: u32::from(options.lc),
                lp: u32::from(options.lp),
                pb: u32::from(options.pb),
                mode: options.mode,
                nice_len: u32::from(options.nice_len),
                mf: options.mf,
                depth_limit: i32::from(options.depth_limit),
            },
        );

        #[rustfmt::skip]
        let chain = match options.prefilter {
            Prefilter::None => Writer::Lzma(lzma_writer),
            Prefilter::BcjX86 => Writer::BcjX86(BCJWriter::new_x86(lzma_writer, 0)),
            Prefilter::BcjArm => Writer::BcjArm(BCJWriter::new_arm(lzma_writer, 0)),
            Prefilter::BcjArmThumb => Writer::BcjArmThumb(BCJWriter::new_arm_thumb(lzma_writer, 0)),
            Prefilter::BcjArm64 => Writer::BcjArm64(BCJWriter::new_arm64(lzma_writer, 0)),
            Prefilter::BcjSparc => Writer::BcjSparc(BCJWriter::new_sparc(lzma_writer, 0)),
            Prefilter::BcjPowerPc => Writer::BcjPowerPc(BCJWriter::new_ppc(lzma_writer, 0)),
            Prefilter::BcjIa64 => Writer::BcjIa64(BCJWriter::new_ia64(lzma_writer, 0)),
            Prefilter::BcjRiscV => Writer::BcjRiscV(BCJWriter::new_riscv(lzma_writer, 0)),
        };

        chain
    }

    /// Finish the writer chain and extract the compressed data.
    fn finish(self) -> Result<Vec<u8>> {
        let ecc_writer = match self {
            Writer::Lzma(writer) => writer.finish()?,
            Writer::BcjX86(writer) => writer.into_inner().finish()?,
            Writer::BcjArm(writer) => writer.into_inner().finish()?,
            Writer::BcjArmThumb(writer) => writer.into_inner().finish()?,
            Writer::BcjArm64(writer) => writer.into_inner().finish()?,
            Writer::BcjSparc(writer) => writer.into_inner().finish()?,
            Writer::BcjPowerPc(writer) => writer.into_inner().finish()?,
            Writer::BcjIa64(writer) => writer.into_inner().finish()?,
            Writer::BcjRiscV(writer) => writer.into_inner().finish()?,
        };

        // Finish the ECCWriter to get the final data.
        ecc_writer.finish()
    }
}

/// A single block writer for TOA format.
///
/// This handles compression, filtering, and hashing for a single block of data.
pub struct TOABlockWriter {
    writer: Option<Writer>,
    options: TOAOptions,
    uncompressed_size: u64,
    current_block_hasher: blake3::Hasher,
    block_size: u64,
    block_offset: u64,
}

impl TOABlockWriter {
    /// Create a new block writer.
    ///
    /// # Parameters
    /// - `options`: Compression options for this block.
    /// - `block_size`: Maximum uncompressed size for this block.
    /// - `block_offset`: The offset of this block in the overall stream (for BLAKE3 chaining).
    pub fn new(options: TOAOptions, block_size: u64, block_offset: u64) -> Self {
        debug_assert_eq!(block_offset % 1024, 0);
        debug_assert_eq!(block_offset % block_size, 0);

        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(block_offset);

        Self {
            writer: Some(Writer::new(&options, block_size, Vec::new())),
            options,
            uncompressed_size: 0,
            current_block_hasher: hasher,
            block_size,
            block_offset,
        }
    }

    /// Get the current uncompressed size written to this block.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Check if this block is full (reached block_size).
    pub fn is_full(&self) -> bool {
        self.uncompressed_size >= self.block_size
    }

    /// Check if this block is empty (no data written).
    pub fn is_empty(&self) -> bool {
        self.uncompressed_size == 0
    }

    /// Reset the block writer for a new block at the given offset.
    fn reset(&mut self, new_block_offset: u64) {
        debug_assert_eq!(self.block_offset % 1024, 0);
        debug_assert!(self.block_offset < new_block_offset);
        debug_assert_eq!(new_block_offset % self.block_size, 0);

        self.writer = Some(Writer::new(&self.options, self.block_size, Vec::new()));
        self.uncompressed_size = 0;
        self.block_offset = new_block_offset;

        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(new_block_offset);
        self.current_block_hasher = hasher;
    }

    /// Finish the current block and write it to the given writer.
    ///
    /// After this call, the block writer is reset and ready for a new block.
    ///
    /// # Parameters
    /// - `output`: The writer to write the complete block to
    /// - `is_final_block`: Whether this is the final block in the stream
    /// - `next_block_offset`: The offset for the next block (for reset)
    ///
    /// # Returns
    /// The BLAKE3 chaining value for this block
    pub fn finish_and_reset<W: Write>(
        &mut self,
        mut output: W,
        is_final_block: bool,
        next_block_offset: u64,
    ) -> Result<[u8; 32]> {
        let compressed_data = if let Some(writer) = self.writer.take() {
            writer.finish()?
        } else {
            Vec::new()
        };

        if !compressed_data.is_empty() {
            let compressed_size = compressed_data.len();

            if compressed_size > (i64::MAX as usize) {
                return Err(crate::error_invalid_data("compressed block too large"));
            }
        }

        let is_partial_block = self.uncompressed_size < self.block_size;

        // For single-block files, we finalize as root. For multi-block files, as chaining value.
        let hash_value = if is_final_block && self.block_offset == 0 {
            *self.current_block_hasher.finalize().as_bytes()
        } else {
            self.current_block_hasher.finalize_non_root()
        };

        let header =
            TOABlockHeader::new(compressed_data.len() as u64, is_partial_block, hash_value);

        let chaining_value = header.blake3_hash();

        header.write(&mut output)?;
        output.write_all(&compressed_data)?;

        // Reset for next block if this isn't the final block.
        if !is_final_block {
            self.writer = Some(Writer::new(&self.options, self.block_size, Vec::new()));
            self.reset(next_block_offset);
        }

        Ok(chaining_value)
    }
}

impl Write for TOABlockWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let space_left = self.block_size.saturating_sub(self.uncompressed_size);
        if space_left == 0 {
            return Err(error_invalid_data("block is full"));
        }

        let write_size = buf.len().min(space_left as usize);
        let write_buf = &buf[..write_size];

        let bytes_written = self
            .writer
            .as_mut()
            .expect("writer should exist")
            .write(write_buf)?;

        self.uncompressed_size += bytes_written as u64;
        self.current_block_hasher
            .update(&write_buf[..bytes_written]);

        Ok(bytes_written)
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(ref mut writer) = self.writer {
            writer.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorCorrection, Prefilter};

    #[test]
    fn test_block_writer_full() {
        let options = TOAOptions {
            prefilter: Prefilter::None,
            dictionary_size_log2: 16,
            lc: 3,
            lp: 0,
            pb: 2,
            error_correction: ErrorCorrection::None,
            ..Default::default()
        };

        let block_size = 10;
        let mut block_writer = TOABlockWriter::new(options, block_size, 0);

        let test_data = b"1234567890"; // Exactly block_size
        let written = block_writer.write(test_data).unwrap();
        assert_eq!(written, test_data.len());
        assert!(block_writer.is_full());

        let result = block_writer.write(b"x");
        assert!(result.is_err());
    }

    #[test]
    fn test_block_writer_reset_and_reuse() {
        let options = TOAOptions {
            prefilter: Prefilter::None,
            dictionary_size_log2: 16,
            lc: 3,
            lp: 0,
            pb: 2,
            error_correction: ErrorCorrection::None,
            ..Default::default()
        };

        let mut block_writer = TOABlockWriter::new(options, 1024, 0);

        let test_data1 = b"First block data";
        block_writer.write_all(test_data1).unwrap();
        assert_eq!(block_writer.uncompressed_size(), test_data1.len() as u64);
        assert!(!block_writer.is_empty());

        let mut output1 = Vec::new();

        let chaining_value1 = block_writer
            .finish_and_reset(&mut output1, false, 1024)
            .unwrap();

        assert_eq!(block_writer.uncompressed_size(), 0);
        assert!(block_writer.is_empty());
        assert_eq!(block_writer.block_offset, 1024);

        let test_data2 = b"Second block data";
        block_writer.write_all(test_data2).unwrap();
        assert_eq!(block_writer.uncompressed_size(), test_data2.len() as u64);

        let mut output2 = Vec::new();
        let chaining_value2 = block_writer
            .finish_and_reset(&mut output2, true, 0)
            .unwrap();

        assert!(!output1.is_empty());
        assert!(!output2.is_empty());
        assert_ne!(chaining_value1, chaining_value2);
        assert_ne!(chaining_value1, [0u8; 32]);
        assert_ne!(chaining_value2, [0u8; 32]);
    }
}
