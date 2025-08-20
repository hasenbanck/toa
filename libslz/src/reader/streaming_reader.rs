use blake3::hazmat::HasherExt;

use super::Reader;
use crate::{
    Read, Result, SLZHeader, cv_stack::CVStack, error_invalid_data, header::SLZBlockHeader,
    lzma::optimized_reader::OptimizedReader, trailer::SLZFileTrailer,
};

/// A single-threaded streaming SLZ decompressor.
pub struct SLZStreamingReader<R> {
    inner: Option<R>,
    header: Option<SLZHeader>,
    current_reader: Option<Reader<R>>,
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

impl<R: OptimizedReader> SLZStreamingReader<R> {
    /// Create a new SLZ reader.
    pub fn new(inner: R, validate_rs: bool) -> Self {
        Self {
            inner: Some(inner),
            header: None,
            current_reader: None,
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
            .ok_or_else(|| error_invalid_data("reader consumed"))?;

        // Read 64 bytes as potential block header or final trailer.
        let mut header_data = [0u8; 64];
        inner.read_exact(&mut header_data)?;

        // Check bit 63 (MSB) to determine if this is a block header or final trailer.
        match (header_data[7] & 0x80) != 0 {
            true => {
                // MSB=1: This is the final trailer.
                self.blocks_finished = true;

                // Add the last blocks hash to the CV stack now that we know it IS the last.
                if let Some(hash) = self.current_block_expected_hash.take() {
                    self.cv_stack.add_chunk_chaining_value(hash, true);
                }

                let trailer = SLZFileTrailer::parse(&header_data, self.validate_rs)?;
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

                let block_header = SLZBlockHeader::parse(&header_data, self.validate_rs)?;
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

                // Create the reader chain.
                let reader = Reader::new(
                    inner,
                    header.prefilter(),
                    header.lc(),
                    header.lp(),
                    header.pb(),
                    header.dict_size(),
                )?;

                self.current_reader = Some(reader);

                Ok(true)
            }
        }
    }

    /// Finish the current block and recover the inner reader.
    fn finish_current_block(&mut self) -> Result<()> {
        if let Some(reader) = self.current_reader.take() {
            let recovered_inner = reader.into_inner();

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

    /// Consume the reader and return the inner reader.
    pub fn into_inner(mut self) -> R {
        if self.current_reader.is_some() {
            let _ = self.finish_current_block();
        }
        self.inner.take().expect("reader was consumed")
    }
}

impl<R: OptimizedReader> Read for SLZStreamingReader<R> {
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
                .ok_or_else(|| error_invalid_data("reader consumed"))?;

            let mut buffer = [0u8; 34];

            if inner.read_exact(&mut buffer).is_err() {
                return Err(error_invalid_data("can't read file header"));
            }

            let header = SLZHeader::parse(&buffer, self.validate_rs)?;

            self.header = Some(header);
        }

        let mut total_read = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // If no current block, try to start the next one.
            if self.current_reader.is_none() && !self.start_next_block()? {
                self.trailer_read = true;
                break;
            }

            if let Some(ref mut reader) = self.current_reader {
                let bytes_read = reader.read(remaining)?;

                if bytes_read == 0 {
                    // Current block exhausted - recover the inner reader.
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
    use std::{
        io::{Cursor, Write},
        ops::Deref,
    };

    use super::*;
    use crate::{
        lzma::optimized_reader::{IoReader, SliceReader},
        writer::{SLZOptions, SLZStreamingWriter},
    };

    #[test]
    fn test_round_trip_empty() {
        let mut compressed = Vec::new();
        let options = SLZOptions::default();

        let writer = SLZStreamingWriter::new(Cursor::new(&mut compressed), options);
        writer.finish().unwrap();

        let slice_reader = SliceReader::new(compressed.deref());
        let mut reader = SLZStreamingReader::new(slice_reader, true);
        let mut decompressed = Vec::new();
        reader.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, Vec::<u8>::new());
    }

    #[test]
    fn test_round_trip_simple_data() {
        let original_data = b"Hello, World! This is a test of SLZ compression.";
        let mut compressed = Vec::new();
        let options = SLZOptions::default();

        let mut writer = SLZStreamingWriter::new(Cursor::new(&mut compressed), options);
        writer.write_all(original_data).unwrap();
        writer.finish().unwrap();

        let io_reader = IoReader::new(compressed.deref());
        let mut reader = SLZStreamingReader::new(io_reader, true);
        let mut decompressed = Vec::new();
        reader.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, original_data);
    }
}
