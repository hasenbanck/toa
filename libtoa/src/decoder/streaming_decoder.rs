use blake3::hazmat::HasherExt;

use super::Decoder;
use crate::{
    Read, Result, TOAHeader, cv_stack::CVStack, error_invalid_data, header::TOABlockHeader,
    trailer::TOAFileTrailer,
};

/// A single-threaded streaming TOA decompressor.
///
/// Validating the data and metadata by setting the `validate_rs` parameter of the factory function
/// to `true` will activate RS verification and error correction, which slows down the decoding
/// speed. To not pay this price, the user should either not validate and instead re-do the
/// decoding in a blake3 hash error case, or use the other decoder, which either have to buffer
/// the data because of multi threading, or can re-read the block by seeking.
pub struct TOAStreamingDecoder<R> {
    inner: Option<R>,
    header: Option<TOAHeader>,
    current_decoder: Option<Decoder<R>>,
    blocks_finished: bool,
    trailer_read: bool,
    current_block_hasher: blake3::Hasher,
    current_block_uncompressed_size: u64,
    current_block_physical_size: u64,
    current_block_expected_hash: Option<[u8; 32]>,
    cv_stack: CVStack,
    total_uncompressed_size: u64,
    validate_rs: bool,
    partial_block_msb_set: bool,
}

impl<R: Read> TOAStreamingDecoder<R> {
    /// Create a new TOA decoder.
    pub fn new(inner: R, validate_rs: bool) -> Self {
        Self {
            inner: Some(inner),
            header: None,
            current_decoder: None,
            blocks_finished: false,
            trailer_read: false,
            current_block_hasher: blake3::Hasher::new(),
            current_block_uncompressed_size: 0,
            current_block_physical_size: 0,
            current_block_expected_hash: None,
            cv_stack: CVStack::new(),
            total_uncompressed_size: 0,
            validate_rs,
            partial_block_msb_set: false,
        }
    }

    fn start_next_block(&mut self) -> Result<bool> {
        if self.blocks_finished {
            return Ok(false);
        }

        let mut inner = self
            .inner
            .take()
            .ok_or_else(|| error_invalid_data("decoder consumed"))?;

        // Read 64 bytes as potential block header or final trailer.
        let mut header_data = [0u8; 64];
        inner.read_exact(&mut header_data)?;

        // Check bit 0 (MSB) to determine if this is a block header or final trailer.
        match (header_data[0] & 0x80) != 0 {
            true => {
                // MSB=1: This is the final trailer.
                self.blocks_finished = true;

                // Add the last blocks hash to the CV stack now that we know it IS the last.
                if let Some(hash) = self.current_block_expected_hash.take() {
                    self.cv_stack.add_chunk_chaining_value(hash, true);
                }

                let trailer = TOAFileTrailer::parse(&header_data, self.validate_rs)?;
                let computed_root_hash = self.cv_stack.finalize();
                self.cv_stack.reset();

                if computed_root_hash != trailer.blake3_hash() {
                    return Err(error_invalid_data("blake3 hash mismatch"));
                }

                self.inner = Some(inner);

                Ok(false)
            }
            false => {
                // MSB=0: This is a block header.
                if self.partial_block_msb_set {
                    return Err(error_invalid_data(
                        "partial blocks only allowed as final block",
                    ));
                }

                // Add the last blocks hash to the CV stack now that we know it IS NOT the last.
                if let Some(pending_hash) = self.current_block_expected_hash.take() {
                    self.cv_stack.add_chunk_chaining_value(pending_hash, false);
                }

                let block_header = TOABlockHeader::parse(&header_data, self.validate_rs)?;
                let physical_size = block_header.physical_size();
                let is_partial_block = block_header.is_partial_block();

                self.partial_block_msb_set = is_partial_block;

                let header = self
                    .header
                    .ok_or_else(|| error_invalid_data("header not read"))?;

                let mut hasher = blake3::Hasher::new();
                hasher.set_input_offset(self.total_uncompressed_size);
                self.current_block_hasher = hasher;

                self.current_block_uncompressed_size = 0;
                self.current_block_physical_size = physical_size;

                // Store the block header hash for later verification.
                self.current_block_expected_hash = Some(block_header.blake3_hash());

                // Create the decoder chain.
                let decoder = Decoder::new(
                    inner,
                    header.prefilter(),
                    header.error_correction(),
                    self.validate_rs,
                    header.lc(),
                    header.lp(),
                    header.pb(),
                    header.dict_size(),
                )?;

                self.current_decoder = Some(decoder);

                Ok(true)
            }
        }
    }

    /// Finish the current block and recover the inner decoder.
    fn finish_current_block(&mut self) -> Result<()> {
        if let Some(decoder) = self.current_decoder.take() {
            let recovered_inner = decoder.into_inner();

            let expected_hash = self
                .current_block_expected_hash
                .ok_or_else(|| error_invalid_data("no expected hash for current block"))?;

            // For the first block, we need to determine if it's a root hash or chaining value.
            if self.cv_stack.is_empty() {
                let hasher_clone = self.current_block_hasher.clone();
                let computed_root_hash = *self.current_block_hasher.finalize().as_bytes();
                let computed_chaining_value = hasher_clone.finalize_non_root();

                if expected_hash != computed_root_hash && expected_hash != computed_chaining_value {
                    return Err(error_invalid_data(
                        "block hash mismatch with expected hash from header",
                    ));
                }
            } else {
                // Subsequent blocks are always chaining values in multi-block files.
                let computed_chaining_value = self.current_block_hasher.finalize_non_root();
                if expected_hash != computed_chaining_value {
                    return Err(error_invalid_data(
                        "block chaining value mismatch with expected hash from header",
                    ));
                }
            };

            self.inner = Some(recovered_inner);
        }
        Ok(())
    }

    /// Consume the decoder and return the inner decoder.
    pub fn into_inner(mut self) -> R {
        if self.current_decoder.is_some() {
            let _ = self.finish_current_block();
        }
        self.inner.take().expect("decoder was consumed")
    }
}

impl<R: Read> Read for TOAStreamingDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // If trailer has been read, we're at EOF.
        if self.trailer_read {
            return Ok(0);
        }

        if self.header.is_none() {
            // No more blocks, verify trailer and finish.
            let inner = self
                .inner
                .as_mut()
                .ok_or_else(|| error_invalid_data("decoder consumed"))?;

            let mut buffer = [0u8; 32];

            if inner.read_exact(&mut buffer).is_err() {
                return Err(error_invalid_data("can't read file header"));
            }

            let header = TOAHeader::parse(&buffer, self.validate_rs)?;

            self.header = Some(header);
        }

        let mut total_read = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // If no current block, try to start the next one.
            if self.current_decoder.is_none() && !self.start_next_block()? {
                self.trailer_read = true;
                break;
            }

            if let Some(ref mut decoder) = self.current_decoder {
                let bytes_read = decoder.read(remaining)?;

                if bytes_read == 0 {
                    // Current block exhausted - recover the inner decoder.
                    self.finish_current_block()?;
                    continue;
                }

                // Update block hasher with uncompressed data
                self.current_block_hasher.update(&remaining[..bytes_read]);
                self.current_block_uncompressed_size += bytes_read as u64;
                self.total_uncompressed_size += bytes_read as u64;

                total_read += bytes_read;
                remaining = &mut remaining[bytes_read..];
            }
        }

        Ok(total_read)
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use crate::encoder::{TOAOptions, TOAStreamingEncoder};

    #[test]
    fn test_round_trip_empty() {
        let mut compressed = Vec::new();
        let options = TOAOptions::default();

        let encoder = TOAStreamingEncoder::new(Cursor::new(&mut compressed), options);
        encoder.finish().unwrap();

        let mut decoder = TOAStreamingDecoder::new(compressed.as_slice(), true);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, Vec::<u8>::new());
    }

    #[test]
    fn test_round_trip_simple_data() {
        let original_data = b"Hello, World! This is a test of TOA compression.";
        let mut compressed = Vec::new();
        let options = TOAOptions::default();

        let mut encoder = TOAStreamingEncoder::new(Cursor::new(&mut compressed), options);
        encoder.write_all(original_data).unwrap();
        encoder.finish().unwrap();

        let mut decoder = TOAStreamingDecoder::new(compressed.as_slice(), true);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, original_data);
    }

    fn test_ecc_round_trip(
        ecc_level: crate::ErrorCorrection,
        data_size: usize,
        pattern_multiplier: u32,
    ) {
        let mut original_data = Vec::new();
        for i in 0..data_size {
            original_data.push(((i as u32 * pattern_multiplier + 13) % 256) as u8);
        }

        let mut compressed = Vec::new();
        let options = TOAOptions::default().with_error_correction(ecc_level);

        let mut encoder = TOAStreamingEncoder::new(Cursor::new(&mut compressed), options);
        encoder.write_all(&original_data).unwrap();
        encoder.finish().unwrap();

        let mut decoder = TOAStreamingDecoder::new(compressed.as_slice(), true);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, original_data);
    }

    #[test]
    fn test_round_trip_standard_ecc() {
        test_ecc_round_trip(crate::ErrorCorrection::Standard, 400, 1);
    }

    #[test]
    fn test_round_trip_paranoid_ecc() {
        test_ecc_round_trip(crate::ErrorCorrection::Paranoid, 350, 7);
    }

    #[test]
    fn test_round_trip_extreme_ecc() {
        test_ecc_round_trip(crate::ErrorCorrection::Extreme, 300, 11);
    }
}
