use super::TOABlockWriter;
use crate::{
    Result, TOAOptions, Write, cv_stack::CVStack, header::TOAHeader, trailer::TOAFileTrailer,
};

/// A single-threaded streaming TOA compressor.
pub struct TOAStreamingEncoder<W> {
    inner: W,
    block_encoder: Option<TOABlockWriter>,
    options: TOAOptions,
    header_written: bool,
    cv_stack: CVStack,
    uncompressed_size: u64,

    block_size: u64,
}

impl<W: Write> TOAStreamingEncoder<W> {
    /// Create a new TOA encoder with the given options.
    pub fn new(inner: W, options: TOAOptions) -> Self {
        let block_size = options.block_size().unwrap_or(u64::MAX / 2);

        Self {
            inner,
            block_encoder: None,
            options,
            header_written: false,
            cv_stack: CVStack::new(),
            uncompressed_size: 0,
            block_size,
        }
    }

    fn write_header(&mut self) -> Result<()> {
        if self.header_written {
            return Ok(());
        }

        let header = TOAHeader::from_options(&self.options);
        header.write(&mut self.inner)?;

        self.header_written = true;
        Ok(())
    }

    fn ensure_block_encoder_exists(&mut self) {
        if self.block_encoder.is_none() {
            let block_encoder =
                TOABlockWriter::new(self.options, self.block_size, self.uncompressed_size);
            self.block_encoder = Some(block_encoder);
        }
    }

    fn finish_current_block(&mut self, is_final_block: bool) -> Result<()> {
        if let Some(ref mut block_encoder) = self.block_encoder {
            let next_block_offset = match is_final_block {
                true => 0,
                false => self.uncompressed_size,
            };

            let chaining_value = block_encoder.finish_and_reset(
                &mut self.inner,
                is_final_block,
                next_block_offset,
            )?;

            self.cv_stack
                .add_chunk_chaining_value(chaining_value, is_final_block);
        }

        Ok(())
    }

    fn write_file_trailer(&mut self) -> Result<()> {
        let root_hash = self.cv_stack.finalize();
        self.cv_stack.reset();

        let trailer = TOAFileTrailer::new(self.uncompressed_size, root_hash);
        trailer.write(&mut self.inner)
    }

    /// Consume the encoder and return the inner encoder.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Finish writing the TOA stream.
    pub fn finish(mut self) -> Result<W> {
        if !self.header_written {
            self.write_header()?;
        }

        if self.block_encoder.is_some() {
            self.finish_current_block(true)?;
        }

        self.write_file_trailer()?;

        Ok(self.into_inner())
    }
}

impl<W: Write> Write for TOAStreamingEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.header_written {
            self.write_header()?;
        }

        self.ensure_block_encoder_exists();

        let mut total_written = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // Check if we need to finish the current block based on uncompressed size limits.
            if let Some(ref block_encoder) = self.block_encoder
                && block_encoder.is_full()
            {
                self.finish_current_block(false)?;
                // Block encoder is automatically reset by finish_and_reset
            }

            let block_encoder = self.block_encoder.as_mut().expect("block encoder not set");
            let bytes_written = block_encoder.write(remaining)?;

            self.uncompressed_size += bytes_written as u64;
            total_written += bytes_written;
            remaining = &remaining[bytes_written..];
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(ref mut block_encoder) = self.block_encoder {
            block_encoder.flush()?;
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
    use crate::{ErrorCorrection, Prefilter, reed_solomon};

    // Specification: Appendix A.1 Minimal File
    #[test]
    fn test_toa_encoder_empty() {
        let expected_compressed: [u8; 96] = hex!(
            "fedcba980100003e5d10a41b4946bc0d
             b0d277d8f82b4b630fbc97d7615530a9
             8000000000000000af1349b9f5f9a1a6
             a0404dea36dcc9499bcb25c9adc112b7
             cc9a93cae41f3262a2b54a54b5f88a30
             271d41dceb661a679fbd77edc3f9040a"
        );
        let expected_header_rs_parity: [u8; 22] =
            hex!("a41b4946bc0db0d277d8f82b4b630fbc97d7615530a9");
        let expected_trailer_blake_hash: [u8; 32] =
            hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        let expected_trailer_rs_parity: [u8; 24] =
            hex!("a2b54a54b5f88a30271d41dceb661a679fbd77edc3f9040a");

        let mut buffer = Vec::new();

        let options = TOAOptions {
            prefilter: Prefilter::None,
            dictionary_size_log2: 16,
            lc: 3,
            lp: 0,
            pb: 2,
            block_size_exponent: None,
            ..Default::default()
        };

        let encoder = TOAStreamingEncoder::new(Cursor::new(&mut buffer), options);
        let _ = encoder.finish().unwrap();

        assert_eq!(buffer.len(), 96, "Total file size should be 96 bytes");

        let (header, trailer) = buffer.split_at(32);
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
        let size_value = u64::from_be_bytes([
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
    fn test_toa_encoder_zero_byte() {
        let expected_compressed: [u8; 165] = hex!(
            "fedcba980100011f5d1e884b0ed50069
             d44c9ae6faa030510e67da670b3259a2
             40000000000000052d3adedff11b61f1
             4c886e35afa036736dcd87a74d27b5c1
             510225d0f592e21319fd6b0ccec085a0
             1fe8fcbdaeca06f1572e90fee6bee37e
             200000000080000000000000012d3ade
             dff11b61f14c886e35afa036736dcd87
             a74d27b5c1510225d0f592e2137e40e1
             6f84c3e6a17e3c65da1f2c61ddd66d5f
             4a662c32b9"
        );
        let expected_header_rs_parity: [u8; 22] =
            hex!("884b0ed50069d44c9ae6faa030510e67da670b3259a2");
        let expected_trailer_blake_hash: [u8; 32] =
            hex!("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
        let expected_trailer_rs_parity: [u8; 24] =
            hex!("7e40e16f84c3e6a17e3c65da1f2c61ddd66d5f4a662c32b9");

        let mut buffer = Vec::new();

        let options = TOAOptions {
            prefilter: Prefilter::BcjX86,
            dictionary_size_log2: 30,
            lc: 3,
            lp: 0,
            pb: 2,
            block_size_exponent: Some(31),
            ..Default::default()
        };

        let mut encoder = TOAStreamingEncoder::new(Cursor::new(&mut buffer), options);
        encoder.write_all(&[0x00]).unwrap();
        let _ = encoder.finish().unwrap();

        assert_eq!(buffer.len(), 165, "Total file size should be 165 bytes");

        let (header, rest) = buffer.split_at(32);
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

        let physical_size_with_flags = u64::from_be_bytes([
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

        assert_eq!(physical_size, 5, "Physical size should be 5");

        let (block_data, trailer) = after_block_header.split_at(5);

        assert_eq!(block_data, &[0x20, 0x00, 0x00, 0x00, 0x00], "LZMA payload");

        assert_eq!(trailer.len(), 64, "Trailer should be exactly 64 bytes");

        let trailer_size_with_flag = u64::from_be_bytes([
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

    fn test_toa_encoder_with_error_correction(
        ecc_level: ErrorCorrection,
        expected_capability_bits: u8,
        decode_fn: fn(&mut [u8; 255]) -> Result<bool>,
    ) {
        let mut output = Vec::new();

        let options = TOAOptions::from_preset(3)
            .with_error_correction(ecc_level)
            .with_block_size_exponent(Some(16));

        let mut encoder = TOAStreamingEncoder::new(&mut output, options);

        let test_data = b"Hello, TOA with Reed-Solomon error correction!";
        encoder.write_all(test_data).unwrap();

        encoder.finish().unwrap();

        // 1. TOA header (32 bytes)
        // 2. Block header (64 bytes)
        // 3. Reed-Solomon encoded compressed data (255 bytes)
        // 4. Final trailer (64 bytes)
        assert_eq!(output.len(), 32 + 64 + 255 + 64);

        let capabilities = output[5];
        assert_eq!(capabilities & 0b11, expected_capability_bits);

        let codeword_start = 32 + 64; // After header + block header
        let codeword = &output[codeword_start..codeword_start + 255];

        let mut codeword_copy = [0u8; 255];
        codeword_copy.copy_from_slice(codeword);

        let decode_result = decode_fn(&mut codeword_copy);
        assert!(decode_result.is_ok());
        let corrected = decode_result.unwrap();
        assert!(!corrected);
    }

    #[test]
    fn test_toa_encoder_with_light_error_correction() {
        test_toa_encoder_with_error_correction(
            ErrorCorrection::Light,
            0b01,
            reed_solomon::code_255_239::decode,
        );
    }

    #[test]
    fn test_toa_encoder_with_medium_error_correction() {
        test_toa_encoder_with_error_correction(
            ErrorCorrection::Medium,
            0b10,
            reed_solomon::code_255_223::decode,
        );
    }

    #[test]
    fn test_toa_encoder_with_heavy_error_correction() {
        test_toa_encoder_with_error_correction(
            ErrorCorrection::Heavy,
            0b11,
            reed_solomon::code_255_191::decode,
        );
    }
}
