mod streaming_reader;

pub use streaming_reader::SLZStreamingReader;

use crate::{Read, Result};

/// A reader that limits reading to a specific number of bytes from the underlying reader.
pub struct BlockReader<R> {
    inner: R,
    remaining: u32,
}

impl<R> BlockReader<R> {
    fn new(inner: R, size: u32) -> Self {
        Self {
            inner,
            remaining: size,
        }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for BlockReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }

        let to_read = buf.len().min(self.remaining as usize);
        let bytes_read = self.inner.read(&mut buf[..to_read])?;
        self.remaining -= bytes_read as u32;
        Ok(bytes_read)
    }
}
