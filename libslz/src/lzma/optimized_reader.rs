use std::io::Read;

use crate::{error_eof, error_invalid_data};

/// Trait to allow specializations for implementations that
/// allow direct buffer accesses for a much better optimized hot loop
/// when running using the range decoder.
pub trait OptimizedReader: Read {
    /// Must return without throwing an error. In out of bound or EOF cases, a 1 must be returned.
    /// This makes sure that a "dist overflow" error is returned. Always returning a 0 instead would
    /// lead to an infinite loop.
    #[inline(always)]
    fn read_u8(&mut self) -> u8 {
        // Out of bound reads return an 1, which is fine, since this
        // will let the decoder error out with a "dist overflow" error.
        // Not returning an error results in code that can be better
        // optimized in the hot path and overall 10% better decoding
        // performance.
        let mut buf = [0; 1];
        match self.read_exact(&mut buf) {
            Ok(_) => buf[0],
            Err(_) => 1,
        }
    }

    #[inline(always)]
    fn try_read_u8(&mut self) -> crate::Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[inline(always)]
    fn try_read_u32_be(&mut self) -> crate::Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(buf.as_mut())?;
        Ok(u32::from_be_bytes(buf))
    }

    #[inline(always)]
    fn try_read_u32(&mut self) -> crate::Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(buf.as_mut())?;
        Ok(u32::from_le_bytes(buf))
    }

    #[inline(always)]
    fn try_read_u64(&mut self) -> crate::Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(buf.as_mut())?;
        Ok(u64::from_le_bytes(buf))
    }

    #[inline(always)]
    fn is_buffer(&self) -> bool {
        false
    }

    #[inline(always)]
    fn pos(&self) -> usize {
        unimplemented!("not a buffer reader")
    }

    #[inline(always)]
    fn set_pos(&mut self, _pos: usize) {
        unimplemented!("not a buffer reader")
    }

    #[inline(always)]
    fn buf(&self) -> &[u8] {
        unimplemented!("not a buffer reader")
    }
}

/// Wrapper type for general Read implementer. Provides low optimization.
pub struct IoReader<R: Read>(R);

impl<R: Read> IoReader<R> {
    #[inline(always)]
    pub fn new(reader: R) -> Self {
        Self(reader)
    }

    #[inline(always)]
    pub fn into_inner(self) -> R {
        self.0
    }
}

impl<R: Read> Read for IoReader<R> {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        self.0.read(buf)
    }
}

impl<R: Read> OptimizedReader for IoReader<R> {}

/// Wrapper type for slices data. Provides high optimization.
pub struct SliceReader<'a> {
    slice: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    #[inline(always)]
    pub fn new(slice: &'a [u8]) -> Self {
        Self { slice, pos: 0 }
    }

    #[inline(always)]
    pub fn into_inner(self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> Read for SliceReader<'a> {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        let available = self.slice.len().saturating_sub(self.pos);
        let to_read = buf.len().min(available);

        if to_read > 0 {
            buf[..to_read].copy_from_slice(&self.slice[self.pos..self.pos + to_read]);
            self.pos += to_read;
        }

        Ok(to_read)
    }
}

impl<'a> OptimizedReader for SliceReader<'a> {
    #[inline(always)]
    fn read_u8(&mut self) -> u8 {
        match self.slice.get(self.pos) {
            Some(&byte) => {
                self.pos += 1;
                byte
            }
            None => {
                // Out of bound reads return an 1, which is fine, since this
                // will let the decoder error out with a "dist overflow" error.
                // Not returning an error results in code that can be better
                // optimized in the hot path and overall 10% better decoding
                // performance.
                1u8
            }
        }
    }

    #[inline(always)]
    fn is_buffer(&self) -> bool {
        true
    }

    #[inline(always)]
    fn pos(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    #[inline(always)]
    fn buf(&self) -> &[u8] {
        self.slice
    }
}

/// Buffered wrapper type for general Read implementer. Provides medium optimization.
pub struct BufferedReader<R> {
    reader: R,
    buffer: Vec<u8>,
    /// Current read position in buffer
    pos: usize,
    /// How much of buffer contains valid data
    filled: usize,
    /// Whether underlying reader reached EOF
    eof: bool,
}

impl<R: Read> BufferedReader<R> {
    const BUFFER_SIZE: usize = 2 * 65536;
    const REFILL_THRESHOLD: usize = 65536;

    pub fn new(mut reader: R) -> crate::Result<Self> {
        let mut buffer = vec![0u8; Self::BUFFER_SIZE];
        let mut filled = 0;
        let mut eof = false;

        // Fill initial buffer.
        while filled < Self::BUFFER_SIZE {
            match reader.read(&mut buffer[filled..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => filled += n,
                Err(e) => return Err(e),
            }
        }

        if filled == 0 {
            return Err(error_invalid_data("no data available"));
        }

        // Resize buffer to actual content if we read less than capacity.
        if eof && filled < Self::BUFFER_SIZE {
            buffer.truncate(filled);
        }

        Ok(Self {
            reader,
            buffer,
            pos: 0,
            filled,
            eof,
        })
    }

    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Ensures at least min_bytes are available starting from current position.
    fn ensure_available(&mut self, min_bytes: usize) -> crate::Result<()> {
        let available = self.filled.saturating_sub(self.pos);

        if available >= min_bytes {
            // Already have enough data.
            return Ok(());
        }

        if self.eof {
            // Can't read more, work with what we have.
            return Ok(());
        }

        // Need to refill buffer.
        self.refill_buffer()
    }

    /// Refills the buffer, compacting if necessary
    fn refill_buffer(&mut self) -> crate::Result<()> {
        if self.eof {
            return Ok(());
        }

        // If we've consumed more than half the buffer, compact it.
        if self.pos > Self::BUFFER_SIZE / 2 {
            let remaining = self.filled - self.pos;
            if remaining > 0 {
                // Move unread data to the beginning
                self.buffer.copy_within(self.pos..self.filled, 0);
            }
            self.filled = remaining;
            self.pos = 0;
        }

        // Try to fill the rest with the buffer
        while self.filled < self.buffer.len() {
            match self.reader.read(&mut self.buffer[self.filled..]) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => self.filled += n,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Proactively refill buffer if approaching the end.
    #[inline(always)]
    fn maybe_refill(&mut self) -> crate::Result<()> {
        let remaining = self.filled.saturating_sub(self.pos);
        if remaining < Self::REFILL_THRESHOLD && !self.eof {
            self.refill_buffer()
        } else {
            Ok(())
        }
    }
}

impl<R: Read> Read for BufferedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Ensure we have data available
        self.ensure_available(1)?;

        let available = self.filled.saturating_sub(self.pos);
        if available == 0 {
            return Ok(0);
        }

        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.buffer[self.pos..self.pos + to_read]);
        self.pos += to_read;

        Ok(to_read)
    }
}

impl<R: Read> OptimizedReader for BufferedReader<R> {
    #[inline(always)]
    fn read_u8(&mut self) -> u8 {
        // Proactively refill if approaching buffer end.
        let _ = self.maybe_refill();

        if self.pos < self.filled {
            let byte = self.buffer[self.pos];
            self.pos += 1;
            byte
        } else {
            // Out of bound reads return 1, which will cause dist overflow error.
            1
        }
    }

    #[inline(always)]
    fn try_read_u8(&mut self) -> crate::Result<u8> {
        // Ensure we have at least 1 byte available.
        self.ensure_available(1)?;

        if self.pos < self.filled {
            let byte = self.buffer[self.pos];
            self.pos += 1;
            Ok(byte)
        } else {
            Err(error_eof())
        }
    }

    #[inline(always)]
    fn try_read_u32_be(&mut self) -> crate::Result<u32> {
        self.ensure_available(4)?;

        if self.pos + 4 <= self.filled {
            let bytes = &self.buffer[self.pos..self.pos + 4];
            let value = u32::from_be_bytes(bytes.try_into().unwrap());
            self.pos += 4;
            Ok(value)
        } else {
            Err(error_eof())
        }
    }

    #[inline(always)]
    fn try_read_u32(&mut self) -> crate::Result<u32> {
        self.ensure_available(4)?;

        if self.pos + 4 <= self.filled {
            let bytes = &self.buffer[self.pos..self.pos + 4];
            let value = u32::from_le_bytes(bytes.try_into().unwrap());
            self.pos += 4;
            Ok(value)
        } else {
            Err(error_eof())
        }
    }

    #[inline(always)]
    fn try_read_u64(&mut self) -> crate::Result<u64> {
        self.ensure_available(8)?;

        if self.pos + 8 <= self.filled {
            let bytes = &self.buffer[self.pos..self.pos + 8];
            let value = u64::from_le_bytes(bytes.try_into().unwrap());
            self.pos += 8;
            Ok(value)
        } else {
            Err(error_eof())
        }
    }

    #[inline(always)]
    fn is_buffer(&self) -> bool {
        true
    }

    #[inline(always)]
    fn pos(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    #[inline(always)]
    fn buf(&self) -> &[u8] {
        &self.buffer[..self.filled]
    }
}
