use alloc::vec::Vec;
use core::cell::UnsafeCell;

use crate::{
    ByteWriter, Prefilter, Result, SLZ_MAGIC, SLZ_VERSION, SLZOptions, Write, error_invalid_data,
    header::SLZHeader,
    lzma::{
        DICT_SIZE_MAX, LZMAOptions, LZMAWriter,
        filter::{bcj::BCJWriter, delta::DeltaWriter},
    },
    reed_solomon::encode,
    trailer::SLZTrailer,
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
    hasher: blake3::Hasher,
    current_block_uncompressed_size: u64,
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
            hasher: blake3::Hasher::new(),
            current_block_uncompressed_size: 0,
            uncompressed_size: 0,
            compressed_size: 0,
        }
    }

    /// Write the header.
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
        Ok(())
    }

    fn finish_current_block(&mut self, writer: Writer) -> Result<Vec<u8>> {
        let mut compressed_data = writer.finish()?;

        if !compressed_data.is_empty() {
            let compressed_size = compressed_data.len();

            if compressed_size > u64::MAX as usize {
                // This is theoretical possible for u64::MAX incompressible data and us adding
                // an end of stream marker. Let's for now assume that in for foreseeable future nobody
                // will write that many data in this archive.
                return Err(error_invalid_data("compressed block too large"));
            }

            self.inner.write_u64(compressed_size as u64)?;
            self.inner.write_all(&compressed_data)?;

            self.compressed_size += compressed_size as u64;

            compressed_data.clear();
        }

        Ok(compressed_data)
    }

    fn write_trailer(&mut self) -> Result<()> {
        let computed_hash = self.hasher.finalize();
        let computed_bytes = *computed_hash.as_bytes();

        let trailer = SLZTrailer::new(self.uncompressed_size, computed_bytes);
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
            self.finish_current_block(counting_writer)?;
        }

        self.write_trailer()?;

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
            let block_limit = if let Some(block_size) = self.options.block_size {
                block_size.get()
            } else {
                u64::MAX
            };

            if self.current_block_uncompressed_size >= block_limit {
                // Current block is full, finish it and start a new one.
                if let Some(writer) = self.writer.take() {
                    let buffer = self.finish_current_block(writer)?;
                    self.current_block_uncompressed_size = 0;
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

            self.hasher.update(&remaining[..bytes_written]);

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
    use crate::lzma::EncodeMode;

    // Specification: Appendix A.1 Minimal File
    #[test]
    fn test_slz_writer_empty() {
        let expected_compressed: [u8; 88] = hex!(
            "fedcba9801005d0000000000000000000000000000000000af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262cedfc1cc789afb176bf1fb71a6756a5b315bdbc2322f987ff3aa7b0c7c2a6a7d"
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
            block_size: None,
            ..Default::default()
        };

        let writer = SLZStreamingWriter::new(Cursor::new(&mut buffer), options);
        let _ = writer.finish().unwrap();

        // Total file size should be: 8 (header) + 8 (end marker) + 72 (trailer) = 88 bytes
        assert_eq!(buffer.len(), 88, "Total file size should be 88 bytes");

        let (header, rest) = buffer.split_at(8);
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

        // LZMA properties: 93 ( 2 (pb) * 5 + 0 (lp)) * 9 + 3 (lc)
        assert_eq!(header[6], 0x5D, "LZMA configuration");

        // LZMA dictionary size: 16 - 16 = 0 (1 byte)
        assert_eq!(header[7], 0x00, "LZMA dictionary size should be 0");

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

    // Specification: Appendix A.1 Minimal File
    #[test]
    fn test_slz_writer_zero_byte() {
        let expected_compressed: [u8; 108] = hex!(
            "fedcba9801011f5d0e0b00000000000000000041fef7ffffe0008000000000000000000001000000000000002d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c213b18ea038cbd9669481d7382c07d10c82c200979933423a3340c248382018"
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
            block_size: None,
            ..Default::default()
        };

        let mut writer = SLZStreamingWriter::new(Cursor::new(&mut buffer), options);
        writer.write_all(&[0x00]).unwrap();
        let _ = writer.finish().unwrap();

        // Total file size should be: 9 (header) + 9 byte LZMA stream + 8 (end marker) + 72 (trailer) = 108 bytes
        assert_eq!(buffer.len(), 108, "Total file size should be 108 bytes");

        let (header, rest) = buffer.split_at(9);
        let (blocks, trailer) = rest.split_at(27);

        // Magic bytes: 0xFE 0xDC 0xBA 0x98 (4 bytes)
        assert_eq!(header[0], 0xFE, "Magic byte 0");
        assert_eq!(header[1], 0xDC, "Magic byte 1");
        assert_eq!(header[2], 0xBA, "Magic byte 2");
        assert_eq!(header[3], 0x98, "Magic byte 3");

        // Version: 0x01 (1 byte)
        assert_eq!(header[4], 0x01, "Format version should be 1");

        // Configuration: Delta filter = 0x01 (1 byte)
        assert_eq!(header[5], 0x01, "Configuration: Delta filter");

        // Delta distance of 32: 31 = 0x1F (1 byte)
        assert_eq!(header[6], 0x1F, "Configuration: Delta filter");

        // LZMA properties: 93 ( 2 (pb) * 5 + 0 (lp)) * 9 + 3 (lc)
        assert_eq!(header[7], 0x5D, "LZMA configuration");

        // LZMA dictionary size: 30 - 16 = 14 (1 byte)
        assert_eq!(header[8], 0x0E, "LZMA dictionary size should be 14");

        // LZMA payload
        assert_eq!(blocks[0], 0x0B);

        // End-of-blocks marker: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        assert_eq!(
            &blocks[1..9],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "End-of-blocks marker"
        );

        assert_eq!(trailer.len(), 72, "Trailer should be exactly 72 bytes");

        // Uncompressed size: 1 (8 bytes, little-endian)
        assert_eq!(
            &trailer[0..8],
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "Uncompressed size should be 1"
        );

        // Blake3 hash of empty data (32 bytes)
        assert_eq!(&trailer[8..40], &expected_blake_hash, "Blake3 hash");

        // Reed-Solomon parity (32 bytes)
        assert_eq!(&trailer[40..72], &expected_rs_parity, "RS parity");

        assert_eq!(buffer.as_slice(), expected_compressed);
    }
}
