use alloc::{vec, vec::Vec};
use std::{
    fs::File,
    io::{BufRead, BufReader, Cursor, Write},
};

use super::{BIT_MODEL_TOTAL_BITS, MOVE_BITS, RC_BIT_MODEL_OFFSET, SHIFT_BITS};
use crate::{ByteReader, Read, error_eof, error_invalid_data, error_invalid_input};

pub(crate) struct RangeDecoder<R> {
    inner: R,
    range: u32,
    code: u32,
}

impl<R> RangeDecoder<R> {
    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: RangeReader> RangeDecoder<R> {
    pub(crate) fn new_stream(mut inner: R) -> crate::Result<Self> {
        let b = inner.try_read_u8()?;
        if b != 0x00 {
            return Err(error_invalid_input("range decoder first byte is not zero"));
        }
        let code = inner.try_read_u32_be()?;
        Ok(Self {
            inner,
            code,
            range: 0xFFFFFFFFu32,
        })
    }

    pub(crate) fn is_stream_finished(&self) -> bool {
        self.code == 0
    }
}

impl<R: RangeReader> RangeDecoder<R> {
    #[inline(always)]
    pub(crate) fn normalize(&mut self) {
        if self.range < 0x0100_0000 {
            let b = self.inner.read_u8() as u32;
            self.code = (self.code << SHIFT_BITS) | b;
            self.range <<= SHIFT_BITS;
        }
    }

    #[inline(always)]
    pub(crate) fn decode_bit(&mut self, prob: &mut u16) -> i32 {
        self.normalize();
        let bound = (self.range >> BIT_MODEL_TOTAL_BITS) * (*prob as u32);

        // This mask will be 0 for bit 0, and 0xFFFFFFFF for bit 1.
        let mask = 0u32.wrapping_sub((self.code >= bound) as u32);

        self.range = (bound & !mask) | ((self.range - bound) & mask);
        self.code -= bound & mask;

        let p = *prob as u32;
        let offset = RC_BIT_MODEL_OFFSET & !mask;
        *prob = p.wrapping_sub((p.wrapping_add(offset)) >> MOVE_BITS) as u16;

        (mask & 1) as i32
    }

    pub(crate) fn decode_bit_tree(&mut self, probs: &mut [u16]) -> i32 {
        let mut symbol = 1;
        loop {
            symbol = (symbol << 1) | self.decode_bit(&mut probs[symbol as usize]);
            if symbol >= probs.len() as i32 {
                break;
            }
        }
        symbol - probs.len() as i32
    }

    pub(crate) fn decode_reverse_bit_tree(&mut self, probs: &mut [u16]) -> i32 {
        let mut symbol = 1;
        let mut i = 0;
        let mut result = 0;
        loop {
            let bit = self.decode_bit(&mut probs[symbol as usize]);
            symbol = (symbol << 1) | bit;
            result |= bit << i;
            i += 1;
            if symbol >= probs.len() as i32 {
                break;
            }
        }
        result
    }

    /*
        /// This was the original function, which can't be optimized well
        /// by the x86_64 backend. aarch64 on the other hand optimizes it fine.
        pub(crate) fn decode_direct_bits(&mut self, count: u32) -> i32 {
            let mut result = 0;

            for _ in 0..count {
                self.normalize();
                self.range >>= 1;
                let t = (self.code.wrapping_sub(self.range)) >> 31;
                self.code -= self.range & (t.wrapping_sub(1));
                result = (result << 1) | (1u32.wrapping_sub(t));
            }

            result as _
        }
    */

    pub(crate) fn decode_direct_bits(&mut self, count: u32) -> i32 {
        #[cfg(all(feature = "optimization", target_arch = "aarch64"))]
        {
            if self.inner.is_buffer() && count > 0 {
                return self.decode_direct_bits_aarch64(count);
            }
        }

        #[cfg(all(feature = "optimization", target_arch = "x86_64"))]
        {
            if self.inner.is_buffer() && count > 0 {
                return self.decode_direct_bits_x86_64(count);
            }
        }

        // The following loop is the original function structured in a way,
        // that hopefully the compiler can optimize better.
        let mut result = 0;
        let mut count = count;

        'outer: loop {
            // Fast Path
            while self.range >= 0x0100_0000 {
                if count == 0 {
                    break 'outer;
                }
                count -= 1;

                self.range >>= 1;
                let t = self.code.wrapping_sub(self.range) >> 31;
                self.code -= self.range & t.wrapping_sub(1);
                result = (result << 1) | (1 - t);
            }

            if count == 0 {
                break 'outer;
            }

            // Slow Path
            let b = self.inner.read_u8() as u32;
            self.code = (self.code << SHIFT_BITS) | b;
            self.range <<= SHIFT_BITS;
        }

        result as _
    }

    #[cfg(all(feature = "optimization", target_arch = "aarch64"))]
    #[inline(always)]
    fn decode_direct_bits_aarch64(&mut self, count: u32) -> i32 {
        // Safety: It is critical that we clamp the reading from the buffer inside it bounds.
        // We also give the "nostack, readonly, pure" guarantees that we must not (and are not)
        // violate.
        unsafe {
            let mut result: i32 = 0;
            let mut pos = self.inner.pos();

            let buf = self.inner.buf();
            let buf_ptr = buf.as_ptr();
            let limit = buf.len() - 1;

            core::arch::asm!(r#"
                    // Setup constants
                    mov    {top_value_reg:w}, #{top_value}

                2:
                    // Calculate result = result << 1
                    lsl    {result:w}, {result:w}, #1

                    // Then, calculate the value for "bit == 1" case
                    orr    {result_bit1:w}, {result:w}, #1

                    // Normalize if range is below the top value
                    cmp    {range:w}, {top_value_reg:w}
                    b.hs   3f
                    lsl    {code:w}, {code:w}, #{shift_bits}
                    lsl    {range:w}, {range:w}, #{shift_bits}

                    // To prevent reading past the buffer, we clamp the read index
                    cmp    {pos}, {limit}
                    csel   {clamped_pos}, {limit}, {pos}, hi

                    // Read byte and update code using indexed addressing
                    ldrb   {tmp:w}, [{buf_ptr}, {clamped_pos}]
                    orr    {code:w}, {code:w}, {tmp:w}
                    add    {pos}, {pos}, #1

                3:
                    // Halve the range and check if code < new_range
                    // using a subtraction and flags
                    lsr    {range:w}, {range:w}, #1
                    subs   {tmp:w}, {code:w}, {range:w}

                    // Use CSEL to update code and result without branching
                    csel   {code:w}, {tmp:w}, {code:w}, hs
                    csel   {result:w}, {result_bit1:w}, {result:w}, hs

                    // Decrement loop counter and loop
                    subs   {count:w}, {count:w}, #1
                    b.ne   2b
                "#,
                // Main state registers (inputs and outputs)
                range = inout(reg) self.range,
                code = inout(reg) self.code,
                pos = inout(reg) pos,
                count = inout(reg) count => _,
                result = inout(reg) result,
                // Read-only inputs
                buf_ptr = in(reg) buf_ptr,
                limit = in(reg) limit,
                // Scratch registers
                top_value_reg = out(reg) _,
                clamped_pos = out(reg) _,
                result_bit1 = out(reg) _,
                tmp = out(reg) _,
                // Constants
                top_value = const 0x0100_0000,
                shift_bits = const SHIFT_BITS,
                // Compiler hints
                options(nostack, readonly, pure)
            );

            // We clamp to the size of the buffer because `pos == buf.len()` signals
            // that there is nothing more to read.
            self.inner.set_pos(pos.min(buf.len()));

            result
        }
    }

    #[cfg(all(feature = "optimization", target_arch = "x86_64"))]
    #[inline(always)]
    fn decode_direct_bits_x86_64(&mut self, count: u32) -> i32 {
        // Safety: It is critical that we clamp the reading from the buffer inside it bounds.
        // We also give the "nostack, readonly, pure" guarantees that we must not (and are not)
        // violate.
        unsafe {
            let mut result: i32 = 0;
            let mut pos = self.inner.pos();

            let buf = self.inner.buf();
            let buf_ptr = buf.as_ptr();
            let limit = buf.len() - 1;

            core::arch::asm!(r#"
                2:
                    // First, calculate result = result << 1
                    shl    {result:e}, 1

                    // Then, calculate the value for "bit == 1" case
                    lea    {result_bit1:e}, [{result:e} + 1]

                    // Normalize if range is below the top value
                    cmp    {range:e}, {top_value}
                    jae    3f
                    shl    {code:e}, {shift_bits}
                    shl    {range:e}, {shift_bits}

                    // To prevent reading past the buffer, clamp the read index
                    mov    {clamped_pos}, {pos}
                    cmp    {clamped_pos}, {limit}
                    cmovg  {clamped_pos}, {limit}

                    // Read byte and update code
                    movzx  {tmp_byte:e}, byte ptr [{buf_ptr} + {clamped_pos}]
                    or     {code:e}, {tmp_byte:e}
                    inc    {pos}

                3:
                    // Halve the range and check if code < new_range
                    // using a subtraction and the sign flag (SF).
                    shr    {range:e}, 1
                    mov    {tmp_code:e}, {code:e}
                    sub    {code:e}, {range:e}

                    // Use CMOV to update code and result without branching
                    cmovs  {code:e}, {tmp_code:e}
                    cmovns {result:e}, {result_bit1:e}

                    // Decrement loop counter and loop
                    dec    {count:e}
                    jnz    2b
                "#,
                // Main state registers (inputs and outputs)
                range = inout(reg) self.range,
                code = inout(reg) self.code,
                pos = inout(reg) pos,
                count = inout(reg) count => _,
                result = inout(reg) result,
                // Read-only inputs
                buf_ptr = in(reg) buf_ptr,
                limit = in(reg) limit,
                // Scratch registers for temporaries
                tmp_code = out(reg) _,
                result_bit1 = out(reg) _,
                clamped_pos = out(reg) _,
                tmp_byte = out(reg) _,
                // Constants
                top_value = const 0x0100_0000,
                shift_bits = const SHIFT_BITS,
                // Compiler hints
                options(nostack, readonly, pure)
            );

            // We clamp to the size of the buffer because `pos == buf.len()` signals
            // that there is nothing more to read.
            self.inner.set_pos(pos.min(buf.len()));

            result
        }
    }
}

pub(crate) trait RangeReader {
    fn read_u8(&mut self) -> u8;

    fn try_read_u8(&mut self) -> crate::Result<u8>;

    fn try_read_u32_be(&mut self) -> crate::Result<u32>;

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

struct IoReader<R: Read>(R);

impl<R: Read> IoReader<R> {
    #[inline(always)]
    pub(crate) fn new(reader: R) -> Self {
        Self(reader)
    }
}

impl<R: Read> Read for IoReader<R> {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        self.0.read(buf)
    }
}

impl<R: Read> RangeReader for IoReader<R> {
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
}

struct SliceReader<'a> {
    slice: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    #[inline(always)]
    pub(crate) fn new(slice: &'a [u8]) -> Self {
        Self { slice, pos: 0 }
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

impl<'a> RangeReader for SliceReader<'a> {
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

const BUFFER_SIZE: usize = 64 * 1024;
const REFILL_THRESHOLD: usize = 4096;

pub(crate) struct BufferedReader<R> {
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
    pub(crate) fn new(mut reader: R) -> crate::Result<Self> {
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut filled = 0;
        let mut eof = false;

        // Fill initial buffer.
        while filled < BUFFER_SIZE {
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
        if eof && filled < BUFFER_SIZE {
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

    pub(crate) fn into_inner(self) -> R {
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
        if self.pos > BUFFER_SIZE / 2 {
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
        if remaining < REFILL_THRESHOLD && !self.eof {
            self.refill_buffer()
        } else {
            Ok(())
        }
    }
}

impl<R: Read> RangeReader for BufferedReader<R> {
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
        // Ensure we have at least 4 bytes available
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
