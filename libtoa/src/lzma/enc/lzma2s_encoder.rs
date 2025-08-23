use super::{
    encoder::{LZMAEncoder, LZMAEncoderModes},
    range_enc::{RangeEncoder, RangeEncoderBuffer},
};
use crate::{
    Write,
    lzma::{ByteWriter, LZMAOptions},
};

const COMPRESSED_SIZE_MAX: u32 = 64 << 10; // 64 KiB
const DELTA_COMPRESSED_SIZE_MAX: u32 = COMPRESSED_SIZE_MAX;
const DELTA_COMPRESSED_SIZE_MIN: u32 = DELTA_COMPRESSED_SIZE_MAX - 255;
const DELTA_UNCOMPRESSED_CENTER: u32 = 65536;

/// A single-threaded LZMA2s compressor.
pub struct LZMA2sEncoder<W: Write> {
    inner: W,
    rc: RangeEncoder<RangeEncoderBuffer>,
    lzma: LZMAEncoder,
    mode: LZMAEncoderModes,
    pending_size: u32,
    uncompressed_size: u64,
    limit: u64,
}

impl<W: Write> LZMA2sEncoder<W> {
    /// Creates a new LZMA2s encoder that will write compressed data to the given encoder.
    pub fn new(inner: W, limit: u64, options: &LZMAOptions) -> Self {
        let rc = RangeEncoder::new_buffer(COMPRESSED_SIZE_MAX as usize);
        let (lzma, mode) = LZMAEncoder::new(
            options.mode,
            options.lc,
            options.lp,
            options.pb,
            options.mf,
            options.depth_limit,
            options.dict_size,
            options.nice_len as usize,
        );

        Self {
            inner,
            rc,
            lzma,
            mode,
            pending_size: 0,
            uncompressed_size: 0,
            limit,
        }
    }

    fn write_compressed(
        &mut self,
        uncompressed_size: u32,
        compressed_size: u32,
    ) -> crate::Result<()> {
        match (DELTA_COMPRESSED_SIZE_MIN..=DELTA_COMPRESSED_SIZE_MAX).contains(&compressed_size) {
            true => {
                let delta = (DELTA_COMPRESSED_SIZE_MAX - compressed_size) as u8;
                let control = 0x60 | ((uncompressed_size - 1) >> 16) as u8 & 0x1F;

                let mut chunk_header = [0u8; 4];
                chunk_header[0] = control;
                chunk_header[1] = ((uncompressed_size - 1) >> 8) as u8;
                chunk_header[2] = (uncompressed_size - 1) as u8;
                chunk_header[3] = delta;
                self.inner.write_all(&chunk_header)?;
            }
            false => {
                let control = 0x40 | ((uncompressed_size - 1) >> 16) as u8 & 0x1F;

                let mut chunk_header = [0u8; 5];
                chunk_header[0] = control;
                chunk_header[1] = ((uncompressed_size - 1) >> 8) as u8;
                chunk_header[2] = (uncompressed_size - 1) as u8;
                chunk_header[3] = ((compressed_size - 1) >> 8) as u8;
                chunk_header[4] = (compressed_size - 1) as u8;
                self.inner.write_all(&chunk_header)?;
            }
        }

        self.rc.write_to(&mut self.inner)
    }

    fn write_uncompressed(&mut self, uncompressed_size: u32) -> crate::Result<()> {
        let delta = (DELTA_UNCOMPRESSED_CENTER as i32) - (uncompressed_size as i32);

        match delta.abs() <= 8191 {
            true => {
                let (sign, magnitude) = match delta >= 0 {
                    true => (0u8, delta as u16),
                    false => (1u8, (-delta) as u16),
                };

                let control = 0x80 | (sign << 6) | ((magnitude >> 8) as u8 & 0x3F);
                self.inner.write_u8(control)?;
                self.inner.write_u8((magnitude & 0xFF) as u8)?;
            }
            false => {
                let encoded = uncompressed_size - 1;
                let control = 0x20 | ((encoded >> 16) as u8 & 0x1F);
                self.inner.write_u8(control)?;
                self.inner.write_u8((encoded >> 8) as u8)?;
                self.inner.write_u8(encoded as u8)?;
            }
        }

        self.lzma.lz.copy_uncompressed(
            &mut self.inner,
            uncompressed_size as i32,
            uncompressed_size as usize,
        )
    }

    fn write_chunk(&mut self) -> crate::Result<()> {
        let compressed_size = self.rc.finish_buffer()?.unwrap_or_default() as u32;
        let mut uncompressed_size = self.lzma.data.uncompressed_size;

        debug_assert!(compressed_size > 0);
        debug_assert!(
            uncompressed_size > 0,
            "uncompressed_size is 0, read_pos={}",
            self.lzma.lz.read_pos,
        );

        let compressed_total =
            if (DELTA_COMPRESSED_SIZE_MIN..=DELTA_COMPRESSED_SIZE_MAX).contains(&compressed_size) {
                4 + compressed_size
            } else {
                5 + compressed_size
            };

        let uncompressed_total = if uncompressed_size.abs_diff(65536) <= 8191 {
            2 + uncompressed_size
        } else {
            3 + uncompressed_size
        };

        if compressed_total < uncompressed_total {
            self.write_compressed(uncompressed_size, compressed_size)?;
        } else {
            self.lzma.reset(&mut self.mode);
            uncompressed_size = self.lzma.data.uncompressed_size;
            debug_assert!(uncompressed_size > 0);
            self.write_uncompressed(uncompressed_size)?;
        }

        self.pending_size -= uncompressed_size;
        self.uncompressed_size += uncompressed_size as u64;

        self.lzma.reset_uncompressed_size();
        self.rc.reset_buffer();

        Ok(())
    }

    /// Finishes the compression and returns the underlying encoder.
    pub fn finish(mut self) -> crate::Result<W> {
        self.lzma.lz.set_finishing();

        while self.pending_size > 0 {
            self.lzma.encode_for_lzma2(&mut self.rc, &mut self.mode)?;
            self.write_chunk()?;
        }

        // Finish with an end-of-stream control byte.
        self.inner.write_u8(0x00)?;

        Ok(self.inner)
    }
}

impl<W: Write> Write for LZMA2sEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        let mut len = buf.len();

        let mut off = 0;
        while len > 0 {
            if self.uncompressed_size >= self.limit {
                // We finished the block.
                return Ok(off);
            }

            let used = self.lzma.lz.fill_window(&buf[off..(off + len)]);
            off += used;
            len -= used;
            self.pending_size += used as u32;

            if self.lzma.encode_for_lzma2(&mut self.rc, &mut self.mode)? {
                self.write_chunk()?;
            }
        }

        Ok(off)
    }

    fn flush(&mut self) -> crate::Result<()> {
        self.lzma.lz.set_flushing();

        while self.pending_size > 0 {
            self.lzma.encode_for_lzma2(&mut self.rc, &mut self.mode)?;
            self.write_chunk()?;
        }

        self.inner.flush()
    }
}
