use alloc::vec::Vec;

use blake3::hazmat::{ChainingValue, HasherExt};

use crate::{
    ByteWriter, Prefilter, Result, SLZOptions, Write, error_invalid_data,
    header::SLZHeader,
    lzma::{
        LZMAOptions, LZMAWriter,
        filter::{bcj::BCJWriter, delta::DeltaWriter},
    },
    resolve_cv_stack,
    trailer::{SLZBlockTrailer, SLZFileTrailer},
};

/// All possible writer combination.
#[allow(clippy::large_enum_variant)]
enum Writer {
    Lzma(LZMAWriter<Vec<u8>>),
    Delta(DeltaWriter<LZMAWriter<Vec<u8>>>),
    BcjX86(BCJWriter<LZMAWriter<Vec<u8>>>),
    BcjArm(BCJWriter<LZMAWriter<Vec<u8>>>),
    BcjArmThumb(BCJWriter<LZMAWriter<Vec<u8>>>),
    BcjArm64(BCJWriter<LZMAWriter<Vec<u8>>>),
    BcjSparc(BCJWriter<LZMAWriter<Vec<u8>>>),
    BcjPowerPc(BCJWriter<LZMAWriter<Vec<u8>>>),
    BcjIa64(BCJWriter<LZMAWriter<Vec<u8>>>),
    BcjRiscV(BCJWriter<LZMAWriter<Vec<u8>>>),
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            Writer::Lzma(writer) => writer.write(buf),
            Writer::Delta(writer) => writer.write(buf),
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
            Writer::Delta(writer) => writer.flush(),
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
        let lzma_writer = LZMAWriter::new_no_header(
            buffer,
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
            Prefilter::Delta { distance } => Writer::Delta(DeltaWriter::new(lzma_writer, distance as usize)),
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

    /// Finish the writer chain and extract the compressed data
    fn finish(self) -> Result<Vec<u8>> {
        match self {
            Writer::Lzma(writer) => writer.finish(),
            Writer::Delta(writer) => writer.into_inner().finish(),
            Writer::BcjX86(writer) => writer.into_inner().finish(),
            Writer::BcjArm(writer) => writer.into_inner().finish(),
            Writer::BcjArmThumb(writer) => writer.into_inner().finish(),
            Writer::BcjArm64(writer) => writer.into_inner().finish(),
            Writer::BcjSparc(writer) => writer.into_inner().finish(),
            Writer::BcjPowerPc(writer) => writer.into_inner().finish(),
            Writer::BcjIa64(writer) => writer.into_inner().finish(),
            Writer::BcjRiscV(writer) => writer.into_inner().finish(),
        }
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
    block_chaining_values: Vec<[u8; 32]>,
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
            block_chaining_values: Vec::new(),
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

            // Set MSB flag for partial blocks (only allowed for final block)
            let size_with_flag = if is_partial_block {
                if !is_final_block {
                    return Err(error_invalid_data(
                        "partial blocks only allowed as final block",
                    ));
                }
                // Set MSB by making the value negative in i64, then cast to u64.
                (-(compressed_size as i64)) as u64
            } else {
                compressed_size as u64
            };

            self.inner.write_u64(size_with_flag)?;
            self.inner.write_all(&compressed_data)?;

            // For single-block files, we finalize as root. For multi-block files, as chaining value.
            let hash_value = if is_final_block && self.block_chaining_values.is_empty() {
                *self.current_block_hasher.finalize().as_bytes()
            } else {
                self.current_block_hasher.finalize_non_root()
            };

            self.block_chaining_values.push(hash_value);

            let trailer = SLZBlockTrailer::new(hash_value);
            trailer.write(&mut self.inner)?;

            self.compressed_size += compressed_size as u64;

            // Reset for next block.
            self.current_block_uncompressed_size = 0;
            compressed_data.clear();
        }

        Ok(compressed_data)
    }

    fn write_file_trailer(&mut self) -> Result<()> {
        // Compute root hash by merging all block chaining values
        let root_hash = if self.block_chaining_values.is_empty() {
            // Empty file case - hash of empty data
            *blake3::Hasher::new().finalize().as_bytes()
        } else if self.block_chaining_values.len() == 1 {
            // Single block file - the block already contains the root hash
            self.block_chaining_values[0]
        } else {
            // Multi-block file - merge chaining values
            self.merge_chaining_values()?
        };

        let trailer = SLZFileTrailer::new(self.uncompressed_size, root_hash);
        trailer.write(&mut self.inner)
    }

    /// Use BLAKE3's hazmat module to properly merge chaining values.
    fn merge_chaining_values(&self) -> Result<[u8; 32]> {
        let cv_stack: Vec<ChainingValue> = self
            .block_chaining_values
            .iter()
            .map(|&bytes| ChainingValue::from(bytes))
            .collect();

        resolve_cv_stack(cv_stack)
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
            // Determine if this is a partial block based on the block size
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
                    // Full blocks are never partial (they're exactly block_size)
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

    // Specification: Appendix A.1 Minimal File
    #[test]
    fn test_slz_writer_empty() {
        let expected_compressed: [u8; 89] = hex!(
            "fedcba9801003e5d1000000000000000
             000000000000000000af1349b9f5f9a1
             a6a0404dea36dcc9499bcb25c9adc112
             b7cc9a93cae41f3262cedfc1cc789afb
             176bf1fb71a6756a5b315bdbc2322f98
             7ff3aa7b0c7c2a6a7d"
        );
        let expected_blake_hash: [u8; 32] =
            hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        let expected_rs_parity: [u8; 32] =
            hex!("cedfc1cc789afb176bf1fb71a6756a5b315bdbc2322f987ff3aa7b0c7c2a6a7d");

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

        // Total file size should be: 9 (header) + 8 (end marker) + 72 (trailer) = 89 bytes
        assert_eq!(buffer.len(), 89, "Total file size should be 89 bytes");

        let (header, rest) = buffer.split_at(9);
        let (blocks, trailer) = rest.split_at(8);

        // Magic bytes: 0xFE 0xDC 0xBA 0x98 (4 bytes)
        assert_eq!(header[0], 0xFE, "Magic byte 0");
        assert_eq!(header[1], 0xDC, "Magic byte 1");
        assert_eq!(header[2], 0xBA, "Magic byte 2");
        assert_eq!(header[3], 0x98, "Magic byte 3");

        // Version: 0x01 (1 byte)
        assert_eq!(header[4], 0x01, "Format version should be 1");

        // Configuration: No prefilter = 0x00 (1 byte)
        assert_eq!(header[5], 0x00, "Configuration: No prefilter");

        // Block size exponent: 62 (1 byte) - Default from header creation
        assert_eq!(header[6], 62, "Block size exponent should be 62");

        // LZMA properties: 93 ( 2 (pb) * 5 + 0 (lp)) * 9 + 3 (lc)
        assert_eq!(header[7], 0x5D, "LZMA configuration");

        // LZMA dictionary size: 16 (1 byte)
        assert_eq!(header[8], 16, "LZMA dictionary size should be 16");

        // End-of-blocks marker: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        assert_eq!(
            blocks,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "End-of-blocks marker"
        );

        assert_eq!(trailer.len(), 72, "Trailer should be exactly 72 bytes");

        // Uncompressed size: 0 (8 bytes, little-endian)
        assert_eq!(
            &trailer[0..8],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "Uncompressed size should be 0"
        );

        // Blake3 hash of empty data (32 bytes)
        assert_eq!(&trailer[8..40], &expected_blake_hash, "Blake3 hash");

        // Reed-Solomon parity (32 bytes)
        assert_eq!(&trailer[40..72], &expected_rs_parity, "RS parity");

        assert_eq!(buffer.as_slice(), expected_compressed);
    }

    // Test with single byte - now includes block trailer
    #[test]
    fn test_slz_writer_zero_byte() {
        let expected_compressed: [u8; 173] = hex!(
            "fedcba9801011f5d1e1ff5ffffffffff
             ffff000041fef7ffffe00080002d3ade
             dff11b61f14c886e35afa036736dcd87
             a74d27b5c1510225d0f592e213c213b1
             8ea038cbd9669481d7382c07d10c82c2
             00979933423a3340c248382018000000
             000000000001000000000000002d3ade
             dff11b61f14c886e35afa036736dcd87
             a74d27b5c1510225d0f592e213c213b1
             8ea038cbd9669481d7382c07d10c82c2
             00979933423a3340c248382018"
        );
        let expected_blake_hash: [u8; 32] =
            hex!("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
        let expected_rs_parity: [u8; 32] =
            hex!("c213b18ea038cbd9669481d7382c07d10c82c200979933423a3340c248382018");

        let mut buffer = Vec::new();

        let options = SLZOptions {
            prefilter: Prefilter::Delta { distance: 32 },
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

        // Total file size should be:
        //  10 (header with delta properties) +
        //  83 (block with size + compressed data + block trailer) +
        //   8 (end marker) +
        //  72 (final trailer)
        // = 173 bytes (actual measured)
        assert_eq!(buffer.len(), 173, "Total file size should be 173 bytes");

        let (header, rest) = buffer.split_at(10);

        // Block structure: 8 bytes size + 11 bytes compressed data + 64 bytes block trailer = 83 bytes total
        let (block_section, final_section) = rest.split_at(83);

        // Then: 8 bytes end marker + 72 bytes final trailer = 80 bytes
        let (end_marker, final_trailer) = final_section.split_at(8);

        // Magic bytes: 0xFE 0xDC 0xBA 0x98 (4 bytes)
        assert_eq!(header[0], 0xFE, "Magic byte 0");
        assert_eq!(header[1], 0xDC, "Magic byte 1");
        assert_eq!(header[2], 0xBA, "Magic byte 2");
        assert_eq!(header[3], 0x98, "Magic byte 3");

        // Version: 0x01 (1 byte)
        assert_eq!(header[4], 0x01, "Format version should be 1");

        // Configuration: Delta filter = 0x01 (1 byte)
        assert_eq!(header[5], 0x01, "Configuration: Delta filter");

        // Block size exponent: 31 (1 byte)
        assert_eq!(header[6], 31, "Block size exponent should be 31");

        // LZMA properties: 93 ( 2 (pb) * 5 + 0 (lp)) * 9 + 3 (lc)
        assert_eq!(header[7], 0x5D, "LZMA configuration");

        // LZMA dictionary size: 30 (1 byte)
        assert_eq!(header[8], 30, "LZMA dictionary size should be 30");

        // Delta distance of 32: 31 = 0x1F (1 byte)
        assert_eq!(header[9], 0x1F, "Configuration: Delta filter");

        // Block: 8-byte size field + compressed data + 72-byte block trailer
        let size_with_flag = u64::from_le_bytes([
            block_section[0],
            block_section[1],
            block_section[2],
            block_section[3],
            block_section[4],
            block_section[5],
            block_section[6],
            block_section[7],
        ]);
        let is_partial_block = (size_with_flag as i64) < 0;
        assert!(is_partial_block);
        let block_size = (-(size_with_flag as i64)) as u64;
        assert_eq!(block_size, 11, "Block compressed size should be 11 bytes");

        // LZMA payload
        assert_eq!(
            &block_section[8..19],
            &[
                0x00, 0x00, 0x41, 0xFE, 0xF7, 0xFF, 0xFF, 0xE0, 0x00, 0x80, 0x00
            ]
        );

        // Block trailer starts at offset 8 + 11 = 19
        let block_trailer = &block_section[19..];
        assert_eq!(block_trailer.len(), 64, "Block trailer should be 64 bytes");

        // Block trailer structure: 32 bytes chaining value + 32 bytes RS parity

        // Blake3 hash of empty data (32 bytes)
        assert_eq!(&block_trailer[..32], &expected_blake_hash, "Blake3 hash");

        // Reed-Solomon parity (32 bytes)
        assert_eq!(&block_trailer[32..64], &expected_rs_parity, "RS parity");

        // End-of-blocks marker
        assert_eq!(
            end_marker,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "End-of-blocks marker"
        );

        assert_eq!(
            final_trailer.len(),
            72,
            "Final trailer should be exactly 72 bytes"
        );

        // Total uncompressed size: 1 (8 bytes, little-endian)
        assert_eq!(
            &final_trailer[0..8],
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "Total uncompressed size should be 1"
        );

        // Blake3 hash of empty data (32 bytes)
        assert_eq!(&final_trailer[8..40], &expected_blake_hash, "Blake3 hash");

        // Reed-Solomon parity (32 bytes)
        assert_eq!(&final_trailer[40..72], &expected_rs_parity, "RS parity");

        assert_eq!(buffer.as_slice(), expected_compressed);
    }
}
