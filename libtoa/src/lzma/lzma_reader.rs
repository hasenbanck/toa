use super::{
    DICT_SIZE_MAX, decoder::LZMADecoder, lz::LZDecoder, optimized_reader::OptimizedReader,
    range_dec::RangeDecoder,
};
use crate::{error_invalid_data, error_invalid_input};

fn get_dict_size(dict_size: u32) -> crate::Result<u32> {
    if dict_size > DICT_SIZE_MAX {
        return Err(error_invalid_input("dict size too large"));
    }
    let dict_size = dict_size.max(4096);
    Ok((dict_size + 15) & !15)
}

/// A single-threaded LZMA decompressor.
pub struct LZMAReader<R> {
    lz: LZDecoder,
    rc: RangeDecoder<R>,
    lzma: LZMADecoder,
    end_reached: bool,
    relaxed_end_cond: bool,
    remaining_size: u64,
}

impl<R: OptimizedReader> LZMAReader<R> {
    /// Unwraps the reader, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.rc.into_inner()
    }
}

impl<R: OptimizedReader> LZMAReader<R> {
    fn construct(
        reader: R,
        uncomp_size: u64,
        lc: u32,
        lp: u32,
        pb: u32,
        dict_size: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        if lc > 8 || lp > 4 || pb > 4 {
            return Err(error_invalid_input("invalid lc or lp or pb"));
        }
        let mut dict_size = get_dict_size(dict_size)?;
        if uncomp_size <= u64::MAX / 2 && dict_size as u64 > uncomp_size {
            dict_size = get_dict_size(uncomp_size as u32)?;
        }

        let rc = RangeDecoder::new_stream(reader);
        let rc = match rc {
            Ok(r) => r,
            Err(e) => {
                return Err(e);
            }
        };
        let lz = LZDecoder::new(get_dict_size(dict_size)? as _, preset_dict);
        let lzma = LZMADecoder::new(lc, lp, pb);
        Ok(Self {
            lz,
            rc,
            lzma,
            end_reached: false,
            relaxed_end_cond: true,
            remaining_size: uncomp_size,
        })
    }

    /// Creates a new input stream that decompresses raw LZMA data (no .lzma header) from `reader` optionally with a preset dictionary.
    /// - `reader` - the input stream to read compressed data from.
    /// - `uncomp_size` - the uncompressed size of the data to be decompressed.
    /// - `lc` - the number of literal context bits.
    /// - `lp` - the number of literal position bits.
    /// - `pb` - the number of position bits.
    /// - `dict_size` - the LZMA dictionary size.
    /// - `preset_dict` - preset dictionary or None to use no preset dictionary.
    pub fn new(
        reader: R,
        uncomp_size: u64,
        lc: u32,
        lp: u32,
        pb: u32,
        dict_size: u32,
        preset_dict: Option<&[u8]>,
    ) -> crate::Result<Self> {
        Self::construct(reader, uncomp_size, lc, lp, pb, dict_size, preset_dict)
    }

    fn read_decode(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.end_reached {
            return Ok(0);
        }
        let mut size = 0;
        let mut len = buf.len() as u64;
        let mut off = 0;
        while len > 0 {
            let mut copy_size_max = len;
            if self.remaining_size <= u64::MAX / 2 && self.remaining_size < len {
                copy_size_max = self.remaining_size;
            }
            self.lz.set_limit(copy_size_max as usize);

            match self.lzma.decode(&mut self.lz, &mut self.rc) {
                Ok(_) => {}
                Err(e) => {
                    if self.remaining_size != u64::MAX || !self.lzma.end_marker_detected() {
                        return Err(e);
                    }
                    self.end_reached = true;
                    self.rc.normalize();
                }
            }

            let copied_size = self.lz.flush(buf, off as _) as u64;
            off += copied_size;
            len -= copied_size;
            size += copied_size;
            if self.remaining_size <= u64::MAX / 2 {
                self.remaining_size -= copied_size;
                if self.remaining_size == 0 {
                    self.end_reached = true;
                }
            }

            if self.end_reached {
                if self.lz.has_pending()
                    || (!self.relaxed_end_cond && !self.rc.is_stream_finished())
                {
                    return Err(error_invalid_data("end reached but not decoder finished"));
                }
                return Ok(size as _);
            }
        }
        Ok(size as _)
    }
}

impl<R: OptimizedReader> crate::Read for LZMAReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        self.read_decode(buf)
    }
}
