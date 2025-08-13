use alloc::vec::Vec;

use super::BlockReader;
use crate::{
    ByteReader, Prefilter, Read, Result, SLZ_MAGIC, SLZ_VERSION, error_invalid_data,
    error_unsupported,
    lzma::{
        filter::{bcj::BCJReader, delta::DeltaReader},
        lzma_reader::LZMAReader,
    },
    reed_solomon::decode,
};

/// All possible reader combinations.
#[allow(clippy::large_enum_variant)]
enum Reader<R> {
    Lzma(LZMAReader<BlockReader<R>>),
    Delta(DeltaReader<LZMAReader<BlockReader<R>>>),
    BcjX86(BCJReader<LZMAReader<BlockReader<R>>>),
    BcjArm(BCJReader<LZMAReader<BlockReader<R>>>),
    BcjArmThumb(BCJReader<LZMAReader<BlockReader<R>>>),
    BcjArm64(BCJReader<LZMAReader<BlockReader<R>>>),
    BcjSparc(BCJReader<LZMAReader<BlockReader<R>>>),
    BcjPowerPc(BCJReader<LZMAReader<BlockReader<R>>>),
    BcjIa64(BCJReader<LZMAReader<BlockReader<R>>>),
    BcjRiscV(BCJReader<LZMAReader<BlockReader<R>>>),
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Reader::Lzma(reader) => reader.read(buf),
            Reader::Delta(reader) => reader.read(buf),
            Reader::BcjX86(reader) => reader.read(buf),
            Reader::BcjArm(reader) => reader.read(buf),
            Reader::BcjArmThumb(reader) => reader.read(buf),
            Reader::BcjArm64(reader) => reader.read(buf),
            Reader::BcjSparc(reader) => reader.read(buf),
            Reader::BcjPowerPc(reader) => reader.read(buf),
            Reader::BcjIa64(reader) => reader.read(buf),
            Reader::BcjRiscV(reader) => reader.read(buf),
        }
    }
}

impl<R: Read> Reader<R> {
    /// Create a new reader chain based on the header configuration.
    fn new(
        block_reader: BlockReader<R>,
        prefilter: Prefilter,
        lc: u8,
        lp: u8,
        pb: u8,
        dict_size: u32,
    ) -> Result<Self> {
        let lzma_reader = LZMAReader::new(
            block_reader,
            u64::MAX,
            lc as u32,
            lp as u32,
            pb as u32,
            dict_size,
            None,
        )?;

        #[rustfmt::skip]
        let chain = match prefilter {
            Prefilter::None => Reader::Lzma(lzma_reader),
            Prefilter::Delta { distance } => Reader::Delta(DeltaReader::new(lzma_reader, distance as usize)),
            Prefilter::BcjX86 => Reader::BcjX86(BCJReader::new_x86(lzma_reader, 0)),
            Prefilter::BcjArm => Reader::BcjArm(BCJReader::new_arm(lzma_reader, 0)),
            Prefilter::BcjArmThumb => Reader::BcjArmThumb(BCJReader::new_arm_thumb(lzma_reader, 0)),
            Prefilter::BcjArm64 => Reader::BcjArm64(BCJReader::new_arm64(lzma_reader, 0)),
            Prefilter::BcjSparc => Reader::BcjSparc(BCJReader::new_sparc(lzma_reader, 0)),
            Prefilter::BcjPowerPc => Reader::BcjPowerPc(BCJReader::new_ppc(lzma_reader, 0)),
            Prefilter::BcjIa64 => Reader::BcjIa64(BCJReader::new_ia64(lzma_reader, 0)),
            Prefilter::BcjRiscV => Reader::BcjRiscV(BCJReader::new_riscv(lzma_reader, 0)),
        };

        Ok(chain)
    }

    /// Extract the inner reader from the reader chain.
    fn into_inner(self) -> R {
        match self {
            Reader::Lzma(reader) => reader.into_inner().into_inner(),
            Reader::Delta(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjX86(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjArm(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjArmThumb(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjArm64(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjSparc(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjPowerPc(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjIa64(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjRiscV(reader) => reader.into_inner().into_inner().into_inner(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SLZHeader {
    prefilter: Prefilter,
    lc: u8,
    lp: u8,
    pb: u8,
    dict_size: u32,
}

#[derive(Debug, Clone, Copy)]
struct SLZTrailer {
    uncompressed_size: u64,
    compressed_size: u64,
    blake3_hash: [u8; 32],
    rs_parity: [u8; 32],
}

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

impl<R: Read> SLZStreamingReader<R> {
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

    fn read_header(&mut self) -> Result<SLZHeader> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| error_invalid_data("reader consumed"))?;

        // Read and verify magic bytes.
        let mut magic = [0u8; 4];
        inner.read_exact(&mut magic)?;

        if magic != SLZ_MAGIC {
            return Err(error_invalid_data("invalid SLZ magic bytes"));
        }

        // Read and verify version.
        let version = inner.read_u8()?;
        if version != SLZ_VERSION {
            return Err(error_unsupported("unsupported SLZ version"));
        }

        // Read prefilter configuration.
        let prefilter_byte = inner.read_u8()?;
        let prefilter = match prefilter_byte {
            0x00 => Prefilter::None,
            0x01 => {
                // Delta filter - need to read distance.
                let distance_byte = inner.read_u8()?;
                Prefilter::Delta {
                    distance: (distance_byte as u16) + 1,
                }
            }
            0x02 => Prefilter::BcjX86,
            0x03 => Prefilter::BcjArm,
            0x04 => Prefilter::BcjArmThumb,
            0x05 => Prefilter::BcjArm64,
            0x06 => Prefilter::BcjSparc,
            0x07 => Prefilter::BcjPowerPc,
            0x08 => Prefilter::BcjIa64,
            0x09 => Prefilter::BcjRiscV,
            _ => return Err(error_invalid_data("unsupported prefilter type")),
        };

        // Read LZMA properties.
        let props = inner.read_u8()?;
        let lc = props % 9;
        let temp = props / 9;
        let lp = temp % 5;
        let pb = temp / 5;

        if lc > 8 || lp > 4 || pb > 4 {
            return Err(error_invalid_data("invalid LZMA properties"));
        }

        // Read dictionary size.
        let dict_size_log2 = inner.read_u8()?;
        if dict_size_log2 > 16 {
            return Err(error_invalid_data("invalid dictionary size"));
        }
        let dict_size = 2u32.pow((dict_size_log2 + 16) as u32);

        let header = SLZHeader {
            prefilter,
            lc,
            lp,
            pb,
            dict_size,
        };

        self.header = Some(header);
        Ok(header)
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
        let block_size = inner.read_u32()?;

        if block_size == 0 {
            // End-of-blocks marker.
            self.blocks_finished = true;
            self.inner = Some(inner);
            return Ok(false);
        }

        let header = self
            .header
            .ok_or_else(|| error_invalid_data("header not read"))?;

        // Create a limited reader for this block.
        let block_reader = BlockReader::new(inner, block_size);

        // Create the reader chain.
        let reader = Reader::new(
            block_reader,
            header.prefilter,
            header.lc,
            header.lp,
            header.pb,
            header.dict_size,
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

    /// Read the trailer and verify integrity.
    fn read_trailer(&mut self) -> Result<SLZTrailer> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| error_invalid_data("reader consumed"))?;

        let uncompressed_size = inner.read_u64()?;
        let compressed_size = inner.read_u64()?;

        let mut blake3_hash = [0u8; 32];
        inner.read_exact(&mut blake3_hash)?;

        let mut rs_parity = [0u8; 32];
        inner.read_exact(&mut rs_parity)?;

        Ok(SLZTrailer {
            uncompressed_size,
            compressed_size,
            blake3_hash,
            rs_parity,
        })
    }

    fn verify_trailer(&mut self, trailer: &SLZTrailer) -> Result<()> {
        let computed_hash = self.hasher.finalize();
        let computed_bytes = computed_hash.as_bytes();

        if !self.validate_trailer {
            return match computed_bytes == &trailer.blake3_hash {
                true => Ok(()),
                false => Err(error_invalid_data("Blake3 hash mismatch")),
            };
        }

        let mut codeword = [0u8; 64];
        codeword[..32].copy_from_slice(&trailer.blake3_hash);
        codeword[32..].copy_from_slice(&trailer.rs_parity);

        match decode(&mut codeword) {
            Ok(corrected) => {
                if corrected {
                    eprintln!("Blake3 hash was corrected by the error correction");
                }

                let corrected_hash = &codeword[..32];
                if computed_bytes == corrected_hash {
                    Ok(())
                } else {
                    Err(error_invalid_data("Blake3 hash mismatch"))
                }
            }
            Err(_) => Err(error_invalid_data(
                "Blake3 hash is corrupted and can't be corrected",
            )),
        }
    }

    /// Consume the reader and return the inner reader.
    pub fn into_inner(mut self) -> R {
        if self.current_reader.is_some() {
            let _ = self.finish_current_block();
        }
        self.inner.take().expect("reader was consumed")
    }
}

impl<R: Read> Read for SLZStreamingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // If trailer has been read, we're at EOF.
        if self.trailer_read {
            return Ok(0);
        }

        if self.header.is_none() {
            self.read_header()?;
        }

        let mut total_read = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // If no current block, try to start the next one.
            if self.current_reader.is_none() && !self.start_next_block()? {
                // No more blocks, verify trailer and finish.
                let trailer = self.read_trailer()?;
                self.verify_trailer(&trailer)?;
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
    use std::io::{Cursor, Write};

    use super::*;
    use crate::writer::{SLZOptions, SLZStreamingWriter};

    #[test]
    fn test_round_trip_empty() {
        let mut compressed = Vec::new();
        let options = SLZOptions::default();

        let writer = SLZStreamingWriter::new(Cursor::new(&mut compressed), options);
        writer.finish().unwrap();

        let mut reader = SLZStreamingReader::new(Cursor::new(&compressed), true);
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

        let mut reader = SLZStreamingReader::new(Cursor::new(&compressed), true);
        let mut decompressed = Vec::new();
        reader.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, original_data);
    }
}
