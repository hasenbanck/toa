use alloc::vec::Vec;

use blake3::hazmat::HasherExt;

use crate::{
    Prefilter, Result, TOAOptions, Write,
    encoder::ecc_encoder::ECCEncoder,
    error_invalid_data,
    header::TOABlockHeader,
    lzma::{LZMA2sEncoder, LZMAOptions, filter::bcj::BCJEncoder},
};

/// All possible encoder combination for a single block.
#[allow(clippy::large_enum_variant)]
enum Encoder {
    Lzma(LZMA2sEncoder<ECCEncoder<Vec<u8>>>),
    BcjX86(BCJEncoder<LZMA2sEncoder<ECCEncoder<Vec<u8>>>>),
    BcjArm(BCJEncoder<LZMA2sEncoder<ECCEncoder<Vec<u8>>>>),
    BcjArmThumb(BCJEncoder<LZMA2sEncoder<ECCEncoder<Vec<u8>>>>),
    BcjArm64(BCJEncoder<LZMA2sEncoder<ECCEncoder<Vec<u8>>>>),
    BcjSparc(BCJEncoder<LZMA2sEncoder<ECCEncoder<Vec<u8>>>>),
    BcjPowerPc(BCJEncoder<LZMA2sEncoder<ECCEncoder<Vec<u8>>>>),
    BcjIa64(BCJEncoder<LZMA2sEncoder<ECCEncoder<Vec<u8>>>>),
    BcjRiscV(BCJEncoder<LZMA2sEncoder<ECCEncoder<Vec<u8>>>>),
}

impl Write for Encoder {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            Encoder::Lzma(encoder) => encoder.write(buf),
            Encoder::BcjX86(encoder) => encoder.write(buf),
            Encoder::BcjArm(encoder) => encoder.write(buf),
            Encoder::BcjArmThumb(encoder) => encoder.write(buf),
            Encoder::BcjArm64(encoder) => encoder.write(buf),
            Encoder::BcjSparc(encoder) => encoder.write(buf),
            Encoder::BcjPowerPc(encoder) => encoder.write(buf),
            Encoder::BcjIa64(encoder) => encoder.write(buf),
            Encoder::BcjRiscV(encoder) => encoder.write(buf),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            Encoder::Lzma(encoder) => encoder.flush(),
            Encoder::BcjX86(encoder) => encoder.flush(),
            Encoder::BcjArm(encoder) => encoder.flush(),
            Encoder::BcjArmThumb(encoder) => encoder.flush(),
            Encoder::BcjArm64(encoder) => encoder.flush(),
            Encoder::BcjSparc(encoder) => encoder.flush(),
            Encoder::BcjPowerPc(encoder) => encoder.flush(),
            Encoder::BcjIa64(encoder) => encoder.flush(),
            Encoder::BcjRiscV(encoder) => encoder.flush(),
        }
    }
}

impl Encoder {
    /// Create a new encoder chain based on the options.
    fn new(options: &TOAOptions, block_size: u64, buffer: Vec<u8>) -> Self {
        let ecc_encoder = ECCEncoder::new(buffer, options.error_correction);

        let lzma_encoder = LZMA2sEncoder::new(
            ecc_encoder,
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
            Prefilter::None => Encoder::Lzma(lzma_encoder),
            Prefilter::BcjX86 => Encoder::BcjX86(BCJEncoder::new_x86(lzma_encoder, 0)),
            Prefilter::BcjArm => Encoder::BcjArm(BCJEncoder::new_arm(lzma_encoder, 0)),
            Prefilter::BcjArmThumb => Encoder::BcjArmThumb(BCJEncoder::new_arm_thumb(lzma_encoder, 0)),
            Prefilter::BcjArm64 => Encoder::BcjArm64(BCJEncoder::new_arm64(lzma_encoder, 0)),
            Prefilter::BcjSparc => Encoder::BcjSparc(BCJEncoder::new_sparc(lzma_encoder, 0)),
            Prefilter::BcjPowerPc => Encoder::BcjPowerPc(BCJEncoder::new_ppc(lzma_encoder, 0)),
            Prefilter::BcjIa64 => Encoder::BcjIa64(BCJEncoder::new_ia64(lzma_encoder, 0)),
            Prefilter::BcjRiscV => Encoder::BcjRiscV(BCJEncoder::new_riscv(lzma_encoder, 0)),
        };

        chain
    }

    /// Finish the encoder chain and extract the compressed data.
    fn finish(self) -> Result<Vec<u8>> {
        let ecc_encoder = match self {
            Encoder::Lzma(encoder) => encoder.finish()?,
            Encoder::BcjX86(encoder) => encoder.into_inner().finish()?,
            Encoder::BcjArm(encoder) => encoder.into_inner().finish()?,
            Encoder::BcjArmThumb(encoder) => encoder.into_inner().finish()?,
            Encoder::BcjArm64(encoder) => encoder.into_inner().finish()?,
            Encoder::BcjSparc(encoder) => encoder.into_inner().finish()?,
            Encoder::BcjPowerPc(encoder) => encoder.into_inner().finish()?,
            Encoder::BcjIa64(encoder) => encoder.into_inner().finish()?,
            Encoder::BcjRiscV(encoder) => encoder.into_inner().finish()?,
        };

        // Finish the ECCWriter to get the final data.
        ecc_encoder.finish()
    }
}

/// A single block encoder for TOA format.
///
/// This handles compression, filtering, and hashing for a single block of data.
pub struct TOABlockWriter {
    encoder: Option<Encoder>,
    options: TOAOptions,
    uncompressed_size: u64,
    current_block_hasher: blake3::Hasher,
    block_size: u64,
    block_offset: u64,
}

impl TOABlockWriter {
    /// Create a new block encoder.
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
            encoder: Some(Encoder::new(&options, block_size, Vec::new())),
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

    /// Reset the block encoder for a new block at the given offset.
    fn reset(&mut self, new_block_offset: u64) {
        debug_assert_eq!(self.block_offset % 1024, 0);
        debug_assert!(self.block_offset < new_block_offset);
        debug_assert_eq!(new_block_offset % self.block_size, 0);

        self.encoder = Some(Encoder::new(&self.options, self.block_size, Vec::new()));
        self.uncompressed_size = 0;
        self.block_offset = new_block_offset;

        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(new_block_offset);
        self.current_block_hasher = hasher;
    }

    /// Finish the current block and write it to the given encoder.
    ///
    /// After this call, the block encoder is reset and ready for a new block.
    ///
    /// # Parameters
    /// - `output`: The encoder to write the complete block to
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
        let compressed_data = if let Some(encoder) = self.encoder.take() {
            encoder.finish()?
        } else {
            Vec::new()
        };

        if !compressed_data.is_empty() {
            let compressed_size = compressed_data.len();

            if compressed_size > (i64::MAX as usize) {
                return Err(error_invalid_data("compressed block too large"));
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
            self.encoder = Some(Encoder::new(&self.options, self.block_size, Vec::new()));
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
            .encoder
            .as_mut()
            .expect("encoder should exist")
            .write(write_buf)?;

        self.uncompressed_size += bytes_written as u64;
        self.current_block_hasher
            .update(&write_buf[..bytes_written]);

        Ok(bytes_written)
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(ref mut encoder) = self.encoder {
            encoder.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorCorrection, Prefilter};

    #[test]
    fn test_block_encoder_full() {
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
        let mut block_encoder = TOABlockWriter::new(options, block_size, 0);

        let test_data = b"1234567890"; // Exactly block_size
        let written = block_encoder.write(test_data).unwrap();
        assert_eq!(written, test_data.len());
        assert!(block_encoder.is_full());

        let result = block_encoder.write(b"x");
        assert!(result.is_err());
    }

    #[test]
    fn test_block_encoder_reset_and_reuse() {
        let options = TOAOptions {
            prefilter: Prefilter::None,
            dictionary_size_log2: 16,
            lc: 3,
            lp: 0,
            pb: 2,
            error_correction: ErrorCorrection::None,
            ..Default::default()
        };

        let mut block_encoder = TOABlockWriter::new(options, 1024, 0);

        let test_data1 = b"First block data";
        block_encoder.write_all(test_data1).unwrap();
        assert_eq!(block_encoder.uncompressed_size(), test_data1.len() as u64);
        assert!(!block_encoder.is_empty());

        let mut output1 = Vec::new();

        let chaining_value1 = block_encoder
            .finish_and_reset(&mut output1, false, 1024)
            .unwrap();

        assert_eq!(block_encoder.uncompressed_size(), 0);
        assert!(block_encoder.is_empty());
        assert_eq!(block_encoder.block_offset, 1024);

        let test_data2 = b"Second block data";
        block_encoder.write_all(test_data2).unwrap();
        assert_eq!(block_encoder.uncompressed_size(), test_data2.len() as u64);

        let mut output2 = Vec::new();
        let chaining_value2 = block_encoder
            .finish_and_reset(&mut output2, true, 0)
            .unwrap();

        assert!(!output1.is_empty());
        assert!(!output2.is_empty());
        assert_ne!(chaining_value1, chaining_value2);
        assert_ne!(chaining_value1, [0u8; 32]);
        assert_ne!(chaining_value2, [0u8; 32]);
    }
}
