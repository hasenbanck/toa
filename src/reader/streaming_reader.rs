use alloc::vec::Vec;

use super::Reader;
use crate::{
    ByteReader, Prefilter, Read, Result, SLZ_MAGIC, SLZ_VERSION, SLZHeader, SLZTrailer, blake3,
    error_invalid_data, error_unsupported,
    lzma::{
        filter::{bcj::BCJReader, delta::DeltaReader},
        lzma_reader::LZMAReader,
        optimized_reader::OptimizedReader,
    },
    reed_solomon::decode,
};

/// A single-threaded streaming SLZ decompressor.
pub struct SLZStreamingReader<R> {
    inner: Option<R>,
    header: Option<SLZHeader>,
    current_reader: Option<Reader<R>>,
    blocks_finished: bool,
    trailer_read: bool,
    hasher: blake3::Hasher,
    uncompressed_size: u64,
    validate_trailer: bool,
}

impl<R: OptimizedReader> SLZStreamingReader<R> {
    /// Create a new SLZ reader.
    pub fn new(inner: R, validate_trailer: bool) -> Self {
        Self {
            inner: Some(inner),
            header: None,
            current_reader: None,
            blocks_finished: false,
            trailer_read: false,
            hasher: blake3::Hasher::new(),
            uncompressed_size: 0,
            validate_trailer,
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

        // Read block size.
        let block_size = inner.read_u64()?;

        if block_size == 0 {
            // End-of-blocks marker.
            self.blocks_finished = true;
            self.inner = Some(inner);
            return Ok(false);
        }

        let header = self
            .header
            .ok_or_else(|| error_invalid_data("header not read"))?;

        // Create the reader chain.
        let reader = Reader::new(
            inner,
            header.prefilter,
            header.lc,
            header.lp,
            header.pb,
            header.dict_size(),
        )?;

        self.current_reader = Some(reader);

        Ok(true)
    }

    /// Finish the current block and recover the inner reader.
    fn finish_current_block(&mut self) -> Result<()> {
        if let Some(reader) = self.current_reader.take() {
            let recovered_inner = reader.into_inner();
            self.inner = Some(recovered_inner);
        }
        Ok(())
    }

    fn parse_and_verify_trailer(&mut self) -> Result<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| error_invalid_data("reader consumed"))?;

        let trailer = SLZTrailer::parse(inner)?;

        let computed_bytes;

        #[cfg(not(feature = "blake3"))]
        {
            computed_bytes = self.hasher.finalize();
        }

        #[cfg(feature = "blake3")]
        {
            let computed_hash = self.hasher.finalize();
            computed_bytes = *computed_hash.as_bytes();
        }

        trailer.verify(self.validate_trailer, &computed_bytes)
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

            self.header = Some(SLZHeader::parse(inner)?);
        }

        let mut total_read = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // If no current block, try to start the next one.
            if self.current_reader.is_none() && !self.start_next_block()? {
                self.parse_and_verify_trailer()?;
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

                self.hasher.update(&remaining[..bytes_read]);
                self.uncompressed_size += bytes_read as u64;

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
        lzma::{
            EncodeMode,
            optimized_reader::{IoReader, SliceReader},
        },
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
