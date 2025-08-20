use alloc::vec::Vec;

use blake3::hazmat::HasherExt;

use crate::{
    Prefilter, Result, SLZOptions, Write,
    cv_stack::CVStack,
    error_invalid_data,
    header::{SLZBlockHeader, SLZHeader},
    lzma::{LZMAOptions, LZMAWriter, filter::bcj::BCJWriter},
    trailer::SLZFileTrailer,
    writer::ecc_writer::ECCWriter,
};

/// All possible writer combination.
#[allow(clippy::large_enum_variant)]
enum Writer {
    Lzma(LZMAWriter<ECCWriter<Vec<u8>>>),
    BcjX86(BCJWriter<LZMAWriter<ECCWriter<Vec<u8>>>>),
    BcjArm(BCJWriter<LZMAWriter<ECCWriter<Vec<u8>>>>),
    BcjArmThumb(BCJWriter<LZMAWriter<ECCWriter<Vec<u8>>>>),
    BcjArm64(BCJWriter<LZMAWriter<ECCWriter<Vec<u8>>>>),
    BcjSparc(BCJWriter<LZMAWriter<ECCWriter<Vec<u8>>>>),
    BcjPowerPc(BCJWriter<LZMAWriter<ECCWriter<Vec<u8>>>>),
    BcjIa64(BCJWriter<LZMAWriter<ECCWriter<Vec<u8>>>>),
    BcjRiscV(BCJWriter<LZMAWriter<ECCWriter<Vec<u8>>>>),
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
    fn new(options: &SLZOptions, buffer: Vec<u8>) -> Result<Self> {
        let ecc_writer = ECCWriter::new(buffer, options.error_correction);

        let lzma_writer = LZMAWriter::new_no_header(
            ecc_writer,
            &LZMAOptions {
                dict_size: options.dict_size(),
                lc: u32::from(options.lc),
                lp: u32::from(options.lp),
                pb: u32::from(options.pb),
                mode: options.mode,
                nice_len: u32::from(options.nice_len),
                mf: options.mf,
                depth_limit: i32::from(options.depth_limit),
                preset_dict: None,
            },
            true,
        )?;

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

        Ok(chain)
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

/// A single-threaded streaming SLZ compressor.
pub struct SLZStreamingWriter<W> {
    inner: W,
    writer: Option<Writer>,
    options: SLZOptions,
    header_written: bool,
    current_block_uncompressed_size: u64,
    current_block_hasher: blake3::Hasher,
    cv_stack: CVStack,
    uncompressed_size: u64,
    compressed_size: u64,
}

impl<W: Write> SLZStreamingWriter<W> {
    /// Create a new SLZ writer with the given options.
    pub fn new(inner: W, options: SLZOptions) -> Self {
        Self {
            inner,
            writer: None,
            options,
            header_written: false,
            current_block_uncompressed_size: 0,
            current_block_hasher: blake3::Hasher::new(),
            cv_stack: CVStack::new(),
            uncompressed_size: 0,
            compressed_size: 0,
        }
    }

    fn write_header(&mut self) -> Result<()> {
        if self.header_written {
            return Ok(());
        }

        let header = SLZHeader::from_options(&self.options);
        header.write(&mut self.inner)?;

        self.header_written = true;
        Ok(())
    }

    fn start_new_block(&mut self, buffer: Vec<u8>) -> Result<()> {
        let writer = Writer::new(&self.options, buffer)?;
        self.writer = Some(writer);

        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(self.uncompressed_size);
        self.current_block_hasher = hasher;

        Ok(())
    }

    fn finish_current_block(
        &mut self,
        writer: Writer,
        is_final_block: bool,
        is_partial_block: bool,
    ) -> Result<Vec<u8>> {
        let mut compressed_data = writer.finish()?;

        if !compressed_data.is_empty() {
            let compressed_size = compressed_data.len();

            if compressed_size > (i64::MAX as usize) {
                return Err(error_invalid_data("compressed block too large"));
            }

            if is_partial_block && !is_final_block {
                return Err(error_invalid_data(
                    "partial blocks only allowed as final block",
                ));
            }

            // For single-block files, we finalize as root. For multi-block files, as chaining value.
            let hash_value = if is_final_block && self.cv_stack.is_empty() {
                *self.current_block_hasher.finalize().as_bytes()
            } else {
                self.current_block_hasher.finalize_non_root()
            };

            self.cv_stack
                .add_chunk_chaining_value(hash_value, is_final_block);

            let header = SLZBlockHeader::new(compressed_size as u64, is_partial_block, hash_value);
            header.write(&mut self.inner)?;

            self.inner.write_all(&compressed_data)?;
            self.compressed_size += compressed_size as u64;

            // Reset for next block.
            self.current_block_uncompressed_size = 0;
            compressed_data.clear();
        }

        Ok(compressed_data)
    }

    fn write_file_trailer(&mut self) -> Result<()> {
        let root_hash = self.cv_stack.finalize();
        self.cv_stack.reset();

        let trailer = SLZFileTrailer::new(self.uncompressed_size, root_hash);
        trailer.write(&mut self.inner)
    }

    /// Consume the writer and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Finish writing the SLZ stream.
    pub fn finish(mut self) -> Result<W> {
        if !self.header_written {
            self.write_header()?;
        }

        if let Some(counting_writer) = self.writer.take() {
            // Determine if this is a partial block based on the block size.
            let header = SLZHeader::from_options(&self.options);
            let is_partial_block = self.current_block_uncompressed_size < header.block_size();
            self.finish_current_block(counting_writer, true, is_partial_block)?;
        }

        self.write_file_trailer()?;

        Ok(self.into_inner())
    }
}

impl<W: Write> Write for SLZStreamingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.header_written {
            self.write_header()?;
        }

        if self.writer.is_none() {
            self.start_new_block(Vec::new())?;
        }

        let mut total_written = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // Check if we need to start a new block based on uncompressed size limits.
            let block_limit = if let Some(block_size) = self.options.block_size() {
                block_size
            } else {
                u64::MAX
            };

            if self.current_block_uncompressed_size >= block_limit {
                // Current block is full, finish it and start a new one.
                if let Some(writer) = self.writer.take() {
                    // Full blocks are never partial (they're exactly block_size).
                    let buffer = self.finish_current_block(writer, false, false)?;
                    self.start_new_block(buffer)?;
                }
            }

            let space_left_in_block =
                block_limit.saturating_sub(self.current_block_uncompressed_size);
            let write_size = remaining.len().min(space_left_in_block as usize);

            let bytes_written = self
                .writer
                .as_mut()
                .expect("writer not set")
                .write(&remaining[..write_size])?;

            self.current_block_uncompressed_size += bytes_written as u64;
            self.uncompressed_size += bytes_written as u64;

            self.current_block_hasher
                .update(&remaining[..bytes_written]);

            total_written += bytes_written;
            remaining = &remaining[bytes_written..];
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(ref mut counting_writer) = self.writer {
            counting_writer.flush()?;
        }

        self.inner.flush()
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use hex_literal::hex;

    use super::*;
    use crate::{ErrorCorrection, reed_solomon};

    // Specification: Appendix A.1 Minimal File
    #[test]
    fn test_slz_writer_empty() {
        let expected_compressed: [u8; 98] = hex!(
            "fedcba980100003e5d105dfece87d497a9afa78c
             dc1461ce4fe539745f931a9db6b9000000000000
             0080af1349b9f5f9a1a6a0404dea36dcc9499bcb
             25c9adc112b7cc9a93cae41f32622d4fd07c37b7
             257fe5617d81e7e8a3acb074f24a22f266ac"
        );
        let expected_header_rs_parity: [u8; 24] =
            hex!("5dfece87d497a9afa78cdc1461ce4fe539745f931a9db6b9");
        let expected_trailer_blake_hash: [u8; 32] =
            hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        let expected_trailer_rs_parity: [u8; 24] =
            hex!("2d4fd07c37b7257fe5617d81e7e8a3acb074f24a22f266ac");

        let mut buffer = Vec::new();

        let options = SLZOptions {
            prefilter: Prefilter::None,
            dictionary_size_log2: 16,
            lc: 3,
            lp: 0,
            pb: 2,
            block_size_exponent: None,
            ..Default::default()
        };

        let writer = SLZStreamingWriter::new(Cursor::new(&mut buffer), options);
        let _ = writer.finish().unwrap();

        assert_eq!(buffer.len(), 98, "Total file size should be 98 bytes");

        let (header, trailer) = buffer.split_at(34);
        let (header, header_parity) = header.split_at(10);

        assert_eq!(header[0], 0xFE, "Magic byte 0");
        assert_eq!(header[1], 0xDC, "Magic byte 1");
        assert_eq!(header[2], 0xBA, "Magic byte 2");
        assert_eq!(header[3], 0x98, "Magic byte 3");

        assert_eq!(header[4], 0x01, "Format version should be 1");
        assert_eq!(header[5], 0x00, "Capabilities should be 0x00");
        assert_eq!(header[6], 0x00, "Prefilter: None");
        assert_eq!(header[7], 62, "Block size exponent should be 62");
        assert_eq!(header[8], 0x5D, "LZMA properties byte 1");
        assert_eq!(header[9], 0x10, "LZMA properties byte 2 (dict size log2)");

        assert_eq!(header_parity, expected_header_rs_parity);

        assert_eq!(trailer.len(), 64, "Trailer should be exactly 64 bytes");

        let size_bytes = &trailer[0..8];
        let size_value = u64::from_le_bytes([
            size_bytes[0],
            size_bytes[1],
            size_bytes[2],
            size_bytes[3],
            size_bytes[4],
            size_bytes[5],
            size_bytes[6],
            size_bytes[7],
        ]);
        assert_eq!(
            size_value, 0x8000000000000000u64,
            "Size should have MSB=1 flag set"
        );
        assert_eq!(
            size_value & !(1u64 << 63),
            0,
            "Actual uncompressed size should be 0"
        );

        assert_eq!(&trailer[8..40], &expected_trailer_blake_hash, "Blake3 hash");
        assert_eq!(
            &trailer[40..64],
            &expected_trailer_rs_parity,
            "Reed-Solomon parity"
        );

        assert_eq!(buffer.as_slice(), expected_compressed);
    }

    // Specification: Appendix A.1 Minimal File
    #[test]
    fn test_slz_writer_zero_byte() {
        let expected_compressed: [u8; 173] = hex!(
            "fedcba980100011f5d1e 594220ca22eda2e406c
             46d7fc3f07a2a974d5136eebdadfa0b000000000
             000402d3adedff11b61f14c886e35afa036736dc
             d87a74d27b5c1510225d0f592e213e82fafd5acd
             f4327b2bd4c3f26af861437d52dde78e034b0000
             041fef7ffffe000800001000000000000802d3ad
             edff11b61f14c886e35afa036736dcd87a74d27b
             5c1510225d0f592e213693139d8319b96f905900
             70ba721f06c27e8acea54d2af03"
        );
        let expected_header_rs_parity: [u8; 24] =
            hex!("594220ca22eda2e406c46d7fc3f07a2a974d5136eebdadfa");
        let expected_trailer_blake_hash: [u8; 32] =
            hex!("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
        let expected_trailer_rs_parity: [u8; 24] =
            hex!("693139d8319b96f90590070ba721f06c27e8acea54d2af03");

        let mut buffer = Vec::new();

        let options = SLZOptions {
            prefilter: Prefilter::BcjX86,
            dictionary_size_log2: 30,
            lc: 3,
            lp: 0,
            pb: 2,
            block_size_exponent: Some(31),
            ..Default::default()
        };

        let mut writer = SLZStreamingWriter::new(Cursor::new(&mut buffer), options);
        writer.write_all(&[0x00]).unwrap();
        let _ = writer.finish().unwrap();

        assert_eq!(buffer.len(), 173, "Total file size should be 173 bytes");

        let (header, rest) = buffer.split_at(34);
        let (header, header_parity) = header.split_at(10);

        assert_eq!(header[0], 0xFE, "Magic byte 0");
        assert_eq!(header[1], 0xDC, "Magic byte 1");
        assert_eq!(header[2], 0xBA, "Magic byte 2");
        assert_eq!(header[3], 0x98, "Magic byte 3");

        assert_eq!(header[4], 0x01, "Format version should be 1");
        assert_eq!(header[5], 0x00, "Capabilities should be 0x00");
        assert_eq!(header[6], 0x01, "Prefilter: BcjX86");
        assert_eq!(header[7], 31, "Block size exponent should be 31");
        assert_eq!(header[8], 0x5D, "LZMA properties byte 1");
        assert_eq!(header[9], 30, "LZMA dict size log2 should be 30");

        assert_eq!(header_parity, expected_header_rs_parity);

        let (block_header_section, after_block_header) = rest.split_at(64);

        let physical_size_with_flags = u64::from_le_bytes([
            block_header_section[0],
            block_header_section[1],
            block_header_section[2],
            block_header_section[3],
            block_header_section[4],
            block_header_section[5],
            block_header_section[6],
            block_header_section[7],
        ]);
        assert_eq!(
            physical_size_with_flags & (1u64 << 63),
            0,
            "Bit 63 should be 0 (block header)"
        );
        assert_eq!(
            physical_size_with_flags & (1u64 << 62),
            1u64 << 62,
            "Bit 62 should be 1 (partial block)"
        );

        let physical_size = physical_size_with_flags & !(3u64 << 62); // Clear both flags

        assert_eq!(physical_size, 11, "Physical size should be 11");

        let (block_data, trailer) = after_block_header.split_at(11);

        assert_eq!(
            block_data,
            &[
                0x00, 0x00, 0x41, 0xFE, 0xF7, 0xFF, 0xFF, 0xE0, 0x00, 0x80, 0x00
            ],
            "LZMA payload"
        );

        assert_eq!(trailer.len(), 64, "Trailer should be exactly 64 bytes");

        let trailer_size_with_flag = u64::from_le_bytes([
            trailer[0], trailer[1], trailer[2], trailer[3], trailer[4], trailer[5], trailer[6],
            trailer[7],
        ]);

        assert_eq!(
            trailer_size_with_flag & (1u64 << 63),
            1u64 << 63,
            "Trailer should have MSB=1 flag"
        );

        let uncompressed_size = trailer_size_with_flag & !(1u64 << 63); // Clear flag
        assert_eq!(uncompressed_size, 1, "Uncompressed size should be 1");

        assert_eq!(&trailer[8..40], &expected_trailer_blake_hash, "Blake3 hash");
        assert_eq!(
            &trailer[40..64],
            &expected_trailer_rs_parity,
            "Reed-Solomon parity"
        );

        assert_eq!(buffer.as_slice(), expected_compressed);
    }

    fn test_slz_writer_with_error_correction(
        ecc_level: ErrorCorrection,
        expected_capability_bits: u8,
        decode_fn: fn(&mut [u8; 255]) -> Result<bool>,
    ) {
        let mut output = Vec::new();

        let options = SLZOptions::from_preset(3)
            .with_error_correction(ecc_level)
            .with_block_size_exponent(Some(16));

        let mut writer = SLZStreamingWriter::new(&mut output, options);

        let test_data = b"Hello, SLZ with Reed-Solomon error correction!";
        writer.write_all(test_data).unwrap();

        writer.finish().unwrap();

        // 1. SLZ header (34 bytes)
        // 2. Block header (64 bytes)
        // 3. Reed-Solomon encoded compressed data (255 bytes)
        // 4. Final trailer (64 bytes)
        assert_eq!(output.len(), 34 + 64 + 255 + 64);

        let capabilities = output[5];
        assert_eq!(capabilities & 0b11, expected_capability_bits);

        let codeword_start = 34 + 64; // After header + block header
        let codeword = &output[codeword_start..codeword_start + 255];

        let mut codeword_copy = [0u8; 255];
        codeword_copy.copy_from_slice(codeword);

        let decode_result = decode_fn(&mut codeword_copy);
        assert!(decode_result.is_ok());
        let corrected = decode_result.unwrap();
        assert!(!corrected);
    }

    #[test]
    fn test_slz_writer_with_light_error_correction() {
        test_slz_writer_with_error_correction(
            ErrorCorrection::Light,
            0b01,
            reed_solomon::code_255_239::decode,
        );
    }

    #[test]
    fn test_slz_writer_with_medium_error_correction() {
        test_slz_writer_with_error_correction(
            ErrorCorrection::Medium,
            0b10,
            reed_solomon::code_255_223::decode,
        );
    }

    #[test]
    fn test_slz_writer_with_heavy_error_correction() {
        test_slz_writer_with_error_correction(
            ErrorCorrection::Heavy,
            0b11,
            reed_solomon::code_255_191::decode,
        );
    }
}
