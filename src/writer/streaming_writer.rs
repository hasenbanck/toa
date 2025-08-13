use alloc::vec::Vec;

use super::CountingWriter;
use crate::{
    ByteWriter, Prefilter, Result, SLZ_MAGIC, SLZ_VERSION, SLZOptions, Write, error_invalid_data,
    lzma::{
        DICT_SIZE_MAX, LZMAOptions, LZMAWriter,
        filter::{bcj::BCJWriter, delta::DeltaWriter},
    },
    reed_solomon::encode,
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
    /// Finish the writer chain and extract the compressed data
    fn finish(self) -> Result<Vec<u8>> {
        match self {
            Writer::Lzma(writer) => {
                let buffer = writer.finish()?;
                Ok(buffer)
            }
            Writer::Delta(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
            Writer::BcjX86(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
            Writer::BcjArm(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
            Writer::BcjArmThumb(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
            Writer::BcjArm64(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
            Writer::BcjSparc(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
            Writer::BcjPowerPc(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
            Writer::BcjIa64(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
            Writer::BcjRiscV(writer) => {
                let lzma_writer = writer.into_inner();
                let buffer = lzma_writer.finish()?;
                Ok(buffer)
            }
        }
    }

    /// Create a new writer chain based on the options.
    fn new(options: &SLZOptions, buffer: Vec<u8>) -> Result<Self> {
        let lzma_writer = LZMAWriter::new_no_header(
            buffer,
            &LZMAOptions {
                dict_size: options.dict_size().min(DICT_SIZE_MAX),
                lc: u32::from(options.lc),
                lp: u32::from(options.lp),
                pb: u32::from(options.pb),
                mode: options.mode,
                nice_len: u32::from(options.nice_len),
                mf: options.mf,
                depth_limit: i32::from(options.depth_limit),
                preset_dict: None,
            },
            false,
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
}

/// A single-threaded streaming SLZ compressor.
pub struct SLZStreamingWriter<W> {
    inner: W,
    counting_writer: Option<CountingWriter<Writer>>,
    options: SLZOptions,
    header_written: bool,
    hasher: blake3::Hasher,
    uncompressed_size: u64,
    compressed_size: u64,
}

impl<W: Write> SLZStreamingWriter<W> {
    /// Create a new SLZ writer with the given options.
    pub fn new(inner: W, options: SLZOptions) -> Self {
        Self {
            inner,
            counting_writer: None,
            options,
            header_written: false,
            hasher: blake3::Hasher::new(),
            uncompressed_size: 0,
            compressed_size: 0,
        }
    }

    /// Write the header.
    fn write_header(&mut self) -> Result<()> {
        if self.header_written {
            return Ok(());
        }

        // Magic bytes
        self.inner.write_all(&SLZ_MAGIC)?;

        // Version
        self.inner.write_u8(SLZ_VERSION)?;

        // Prefilter configuration byte
        let config = u8::from(self.options.prefilter);
        self.inner.write_u8(config)?;

        // LZMA properties byte: (pb * 5 + lp) * 9 + lc
        let props = (self.options.pb * 5 + self.options.lp) * 9 + self.options.lc;
        self.inner.write_u8(props)?;

        // Dictionary size: log2 minus 16
        self.inner
            .write_u8(self.options.dictionary_size_log2 - 16)?;

        // Prefilter properties
        if let Prefilter::Delta { distance } = self.options.prefilter {
            self.inner.write_u8(distance as u8 - 1)?;
        }

        self.header_written = true;

        Ok(())
    }

    fn start_new_block(&mut self, buffer: Vec<u8>) -> Result<()> {
        let writer = Writer::new(&self.options, buffer)?;
        self.counting_writer = Some(CountingWriter::new(writer));
        Ok(())
    }

    fn finish_current_block(&mut self, counting_writer: CountingWriter<Writer>) -> Result<Vec<u8>> {
        let mut compressed_data = counting_writer.into_inner().finish()?;

        if !compressed_data.is_empty() {
            if compressed_data.len() > u32::MAX as usize {
                return Err(error_invalid_data("compressed block too large"));
            }

            self.inner.write_u32(compressed_data.len() as u32)?;
            self.inner.write_all(&compressed_data)?;

            self.compressed_size += compressed_data.len() as u64;

            compressed_data.clear();
        }

        Ok(compressed_data)
    }

    fn write_trailer(&mut self) -> Result<()> {
        // Write end-of-blocks marker.
        self.inner.write_u32(0)?;

        // Write size fields.
        self.inner.write_u64(self.uncompressed_size)?;
        self.inner.write_u64(self.compressed_size)?;

        // Finalize Blake3 hash.
        let hash = self.hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Generate Reed-Solomon parity.
        let parity = encode(hash_bytes);

        // Write Blake3 hash.
        self.inner.write_all(hash_bytes)?;

        // Write Reed-Solomon parity.
        self.inner.write_all(&parity)?;

        Ok(())
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

        if let Some(counting_writer) = self.counting_writer.take() {
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

        if self.counting_writer.is_none() {
            self.start_new_block(Vec::new())?;
        }

        let mut total_written = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // Check if we need to start a new block based on uncompressed size limits.
            let block_limit = if let Some(block_size) = self.options.block_size {
                block_size.get() as u64
            } else {
                u32::MAX as u64
            };

            let current_block_size = self
                .counting_writer
                .as_ref()
                .expect("counting writer not set")
                .bytes_written();

            if current_block_size >= block_limit {
                // Current block is full, finish it and start a new one.
                if let Some(counting_writer) = self.counting_writer.take() {
                    let buffer = self.finish_current_block(counting_writer)?;
                    self.start_new_block(buffer)?;
                }
            }

            let bytes_written = self
                .counting_writer
                .as_mut()
                .expect("counting writer not set")
                .write(remaining)?;

            self.hasher.update(&remaining[..bytes_written]);
            self.uncompressed_size += bytes_written as u64;

            total_written += bytes_written;
            remaining = &remaining[bytes_written..];
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(ref mut counting_writer) = self.counting_writer {
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

    #[test]
    fn test_slz_writer_empty() {
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

        let expected_blake_hash: [u8; 32] =
            hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        let expected_rs_parity: [u8; 32] =
            hex!("cedfc1cc789afb176bf1fb71a6756a5b315bdbc2322f987ff3aa7b0c7c2a6a7d");

        // Total file size should be: 8 (header) + 4 (end marker) + 80 (trailer) = 92 bytes
        assert_eq!(buffer.len(), 92, "Total file size should be 92 bytes");

        let (header, rest) = buffer.split_at(8);
        let (blocks, trailer) = rest.split_at(4);

        // Magic bytes: 0xFE 0xDC 0xBA 0x98 (4 bytes)
        assert_eq!(header[0], 0xFE, "Magic byte 0");
        assert_eq!(header[1], 0xDC, "Magic byte 1");
        assert_eq!(header[2], 0xBA, "Magic byte 2");
        assert_eq!(header[3], 0x98, "Magic byte 3");

        // Version: 0x01 (1 byte)
        assert_eq!(header[4], 0x01, "Format version should be 1");

        // Configuration: No prefilter = 0x00 (1 byte)
        assert_eq!(header[5], 0x00, "Configuration: LZMA + no prefilter");

        // LZMA properties: 93 ( 2 (pb) * 5 + 0 (lp)) * 9 + 3 (lc)
        assert_eq!(header[6], 0x5D, "Configuration: LZMA + no prefilter");

        // LZMA dictionary size: 16 - 16 = 0 (1 byte)
        assert_eq!(header[7], 0x00, "LZMA dictionary size should be 0");

        // End-of-blocks marker: 0x00 0x00 0x00 0x00
        assert_eq!(blocks, &[0x00, 0x00, 0x00, 0x00], "End-of-blocks marker");

        assert_eq!(trailer.len(), 80, "Trailer should be exactly 80 bytes");

        // Uncompressed size: 0 (8 bytes, little-endian)
        assert_eq!(
            &trailer[0..8],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "Uncompressed size should be 0"
        );

        // Compressed size: 0 (8 bytes, little-endian)
        assert_eq!(
            &trailer[8..16],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "Compressed size should be 0"
        );

        // Blake3 hash of empty data (32 bytes)
        assert_eq!(&trailer[16..48], &expected_blake_hash, "Blake3 hash");

        // Reed-Solomon parity (32 bytes)
        assert_eq!(&trailer[48..80], &expected_rs_parity, "RS parity");
    }
}
