use super::{ByteDecoder, decoder::LZMADecoder, lz::LZDecoder, range_dec::RangeDecoder};
use crate::{Error, Read, copy_error, error_invalid_input};

pub const COMPRESSED_SIZE_MAX: u32 = 1 << 16;
const DELTA_COMPRESSED_SIZE_MAX: usize = COMPRESSED_SIZE_MAX as usize;

/// A single-threaded LZMA2s decompressor.
pub struct LZMA2sDecoder<R> {
    inner: R,
    lz: LZDecoder,
    rc: RangeDecoder,
    lzma: LZMADecoder,
    uncompressed_size: usize,
    compressed_size: usize,
    is_lzma_chunk: bool,
    end_reached: bool,
    was_uncompressed: bool,
    error: Option<Error>,
}

#[inline]
fn get_dict_size(dict_size: u32) -> u32 {
    (dict_size + 15) & !15
}

impl<R> LZMA2sDecoder<R> {
    /// Unwraps the decoder, returning the underlying decoder.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> LZMA2sDecoder<R> {
    /// Create a new LZMA2s decoder.
    pub fn new(inner: R, lc: u32, lp: u32, pb: u32, dict_size: u32) -> Self {
        let lz = LZDecoder::new(get_dict_size(dict_size) as _, None);
        let rc = RangeDecoder::new_buffer(COMPRESSED_SIZE_MAX as _);
        let lzma = LZMADecoder::new(lc, lp, pb);

        Self {
            inner,
            lz,
            rc,
            lzma,
            uncompressed_size: 0,
            compressed_size: 0,
            is_lzma_chunk: false,
            end_reached: false,
            was_uncompressed: true,
            error: None,
        }
    }

    // # Control byte and chunk overview
    //
    // Bits 7-5: Chunk type
    //   000 = End of stream (no bytes follow)
    //   001 = Uncompressed chunk
    //   010 = Compressed chunk
    //   011 = Delta Compressed chunk (8 bits delta, 4 bytes total)
    //   1XX = Delta Uncompressed chunk (7 bits + 8 bits delta, 2 bytes total)
    //
    // ## End of stream: [00000000]
    //
    // ## Uncompressed chunk: [01ssssss][size_mid][size_lo]
    // - 21 bits total size (up to 2 MiB)
    //
    // ## Compressed chunk: [010uuuuu][uncomp_mid][uncomp_lo][comp_hi][comp_lo]
    // - 21 bits uncompressed size (up to 2 MIB)
    // - 16 bits compressed size (up to 64 KIB)
    //
    // ## Delta Compressed chunk: [011uuuuu][uncomp_mid][uncomp_lo][delta] - 4 bytes total
    // - 21 bits uncompressed size (up to 2 MIB)
    // - Compressed size = 65536 - delta
    //
    // ## Delta uncompressed: [1sdddddd] [dddddddd]
    // - s = sign bit (0=positive, 1=negative from 65536)
    // - 14 bits total magnitude (6+8)
    //
    // LZMA2s only resets the state when switching from a compressed to an uncompressed chunk.
    fn decode_chunk_header(&mut self) -> crate::Result<()> {
        let control = self.inner.read_u8()?;

        // Check bit 7 first for delta uncompressed
        if control & 0x80 != 0 {
            // Delta uncompressed chunk: [1sdddddd] [dddddddd]
            self.is_lzma_chunk = false;

            let sign = (control >> 6) & 0x01;
            let delta_high = (control & 0x3F) as usize;
            let delta_low = self.inner.read_u8()? as usize;
            let delta = (delta_high << 8) | delta_low;

            self.uncompressed_size = if sign == 0 {
                65536 + delta // Positive delta
            } else {
                65536 - delta // Negative delta
            };
            self.compressed_size = 0;

            return Ok(());
        }

        // For other types, check bits 7-5
        let chunk_type = (control >> 5) & 0x07;

        match chunk_type {
            0b000 => {
                // End of stream (control must be exactly 0x00)
                if control == 0x00 {
                    self.end_reached = true;
                    Ok(())
                } else {
                    Err(error_invalid_input("invalid end of stream marker"))
                }
            }
            0b001 => {
                // Uncompressed chunk: [001sssss][size_mid][size_lo]
                self.is_lzma_chunk = false;

                let size_high = (control & 0x1F) as usize;
                let size_mid = self.inner.read_u8()? as usize;
                let size_low = self.inner.read_u8()? as usize;

                self.uncompressed_size = (size_high << 16) | (size_mid << 8) | size_low;
                self.uncompressed_size += 1;
                self.compressed_size = 0;

                Ok(())
            }
            0b010 => {
                // Compressed chunk (normal): [010uuuuu][uncomp_mid][uncomp_lo][comp_hi][comp_lo]
                self.is_lzma_chunk = true;

                let uncompressed_high = (control & 0x1F) as usize;
                let uncompressed_mid = self.inner.read_u8()? as usize;
                let uncompressed_low = self.inner.read_u8()? as usize;
                self.uncompressed_size =
                    (uncompressed_high << 16) | (uncompressed_mid << 8) | uncompressed_low;
                self.uncompressed_size += 1;

                let compressed_high = self.inner.read_u8()? as usize;
                let compressed_low = self.inner.read_u8()? as usize;
                self.compressed_size = (compressed_high << 8) | compressed_low;
                self.compressed_size += 1;

                self.rc.prepare(&mut self.inner, self.compressed_size)
            }
            0b011 => {
                // Delta compressed chunk: [011uuuuu][uncomp_mid][uncomp_lo][delta]
                self.is_lzma_chunk = true;

                let uncompressed_high = (control & 0x1F) as usize;
                let uncompressed_mid = self.inner.read_u8()? as usize;
                let uncompressed_low = self.inner.read_u8()? as usize;
                self.uncompressed_size =
                    (uncompressed_high << 16) | (uncompressed_mid << 8) | uncompressed_low;
                self.uncompressed_size += 1;

                let delta = self.inner.read_u8()? as usize;
                self.compressed_size = DELTA_COMPRESSED_SIZE_MAX - delta;

                self.rc.prepare(&mut self.inner, self.compressed_size)
            }
            _ => Err(error_invalid_input("Invalid chunk type")),
        }
    }

    fn read_decode(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(error) = &self.error {
            return Err(copy_error(error));
        }

        if self.end_reached {
            return Ok(0);
        }

        let mut size = 0;
        let mut len = buf.len();
        let mut off = 0;

        while len > 0 {
            if self.uncompressed_size == 0 {
                self.decode_chunk_header()?;
                if self.end_reached {
                    return Ok(size);
                }

                // Only reset if switching from uncompressed to compressed.
                if self.is_lzma_chunk && self.was_uncompressed {
                    self.lzma.reset();
                }

                self.was_uncompressed = !self.is_lzma_chunk;
            }

            let copy_size_max = self.uncompressed_size.min(len);

            if !self.is_lzma_chunk {
                self.lz.copy_uncompressed(&mut self.inner, copy_size_max)?;
            } else {
                self.lz.set_limit(copy_size_max);
                self.lzma.decode(&mut self.lz, &mut self.rc)?;
            }

            let copied_size = self.lz.flush(buf, off);
            off += copied_size;
            len -= copied_size;
            size += copied_size;
            self.uncompressed_size -= copied_size;

            if self.uncompressed_size == 0
                && self.is_lzma_chunk
                && (!self.rc.is_finished() || self.lz.has_pending())
            {
                return Err(error_invalid_input("chunk data mismatch"));
            }
        }

        Ok(size)
    }
}

impl<R: Read> Read for LZMA2sDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        match self.read_decode(buf) {
            Ok(size) => Ok(size),
            Err(error) => {
                #[cfg(not(feature = "std"))]
                {
                    self.error = Some(error);
                }
                #[cfg(feature = "std")]
                {
                    self.error = Some(Error::new(error.kind(), error.to_string()));
                }
                Err(error)
            }
        }
    }
}
