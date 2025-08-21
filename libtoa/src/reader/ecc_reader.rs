use alloc::vec::Vec;

use crate::{
    ErrorCorrection, Read, Result, error_invalid_data,
    lzma::optimized_reader::OptimizedReader,
    reed_solomon::{code_255_191, code_255_223, code_255_239},
};

type DecodeFunction<R> = fn(&mut ECCReader<R>, &mut [u8]) -> Result<usize>;

fn decode_none<R: OptimizedReader>(reader: &mut ECCReader<R>, buf: &mut [u8]) -> Result<usize> {
    reader.inner.read(buf)
}

fn decode_light<R: OptimizedReader>(reader: &mut ECCReader<R>, buf: &mut [u8]) -> Result<usize> {
    reader.decode_with_rs::<_, 239>(buf, code_255_239::decode)
}

fn decode_medium<R: OptimizedReader>(reader: &mut ECCReader<R>, buf: &mut [u8]) -> Result<usize> {
    reader.decode_with_rs::<_, 223>(buf, code_255_223::decode)
}

fn decode_heavy<R: OptimizedReader>(reader: &mut ECCReader<R>, buf: &mut [u8]) -> Result<usize> {
    reader.decode_with_rs::<_, 191>(buf, code_255_191::decode)
}

/// Error Correction Reader that applies Reed-Solomon decoding to compressed data.
pub(crate) struct ECCReader<R> {
    inner: R,
    decode_fn: DecodeFunction<R>,
    buffer: Vec<u8>,
    buffer_pos: usize,
    codeword_buffer: Vec<u8>,
    validate_rs: bool,
    uses_buffer: bool,
}

impl<R: OptimizedReader> ECCReader<R> {
    /// Create a new ECCReader with the specified error correction level.
    pub(crate) fn new(inner: R, error_correction: ErrorCorrection, validate_rs: bool) -> Self {
        let (decode_fn, uses_buffer) = match error_correction {
            ErrorCorrection::None => (decode_none as DecodeFunction<R>, false),
            ErrorCorrection::Light => (decode_light as DecodeFunction<R>, true),
            ErrorCorrection::Medium => (decode_medium as DecodeFunction<R>, true),
            ErrorCorrection::Heavy => (decode_heavy as DecodeFunction<R>, true),
        };

        let codeword_buffer = match uses_buffer {
            true => {
                vec![0; 255]
            }
            false => Vec::default(),
        };

        Self {
            inner,
            decode_fn,
            buffer: Vec::new(),
            buffer_pos: 0,
            codeword_buffer,
            validate_rs,
            uses_buffer,
        }
    }

    /// Generic Reed-Solomon decoding with configurable data length and decoder function.
    fn decode_with_rs<F, const DATA_LEN: usize>(
        &mut self,
        buf: &mut [u8],
        decode_rs_fn: F,
    ) -> Result<usize>
    where
        F: Fn(&mut [u8; 255]) -> Result<bool>,
    {
        let mut total_read = 0;

        while total_read < buf.len() {
            if self.buffer_pos >= self.buffer.len() {
                let bytes_to_read = 255;
                let mut actual_read = 0;

                while actual_read < bytes_to_read {
                    match self
                        .inner
                        .read(&mut self.codeword_buffer[actual_read..bytes_to_read])
                    {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            actual_read += n;
                        }
                        Err(e) => return Err(e),
                    }
                }

                if actual_read == 0 {
                    // EOF
                    break;
                }

                if actual_read < 255 {
                    // Pad with zeros for partial read.
                    for i in actual_read..255 {
                        self.codeword_buffer[i] = 0;
                    }
                }

                let mut codeword_array = [0u8; 255];
                codeword_array.copy_from_slice(&self.codeword_buffer);

                if self.validate_rs {
                    let corrected = decode_rs_fn(&mut codeword_array).map_err(|_| {
                        error_invalid_data("error correction couldn't correct a faulty block")
                    })?;

                    if corrected {
                        eprint!("Error correction corrected a faulty block");
                    }
                }

                self.buffer.resize(DATA_LEN, 0);
                self.buffer.copy_from_slice(&codeword_array[..DATA_LEN]);

                self.buffer_pos = 0;
            }

            // Copy from buffer to output.
            let available = self.buffer.len() - self.buffer_pos;
            let needed = buf.len() - total_read;
            let to_copy = available.min(needed);

            if to_copy > 0 {
                buf[total_read..total_read + to_copy]
                    .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
                self.buffer_pos += to_copy;
                total_read += to_copy;
            } else {
                break;
            }
        }

        Ok(total_read)
    }

    /// Get the inner reader.
    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: OptimizedReader> Read for ECCReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.uses_buffer {
            return self.inner.read(buf);
        }

        (self.decode_fn)(self, buf)
    }
}

impl<R: OptimizedReader> OptimizedReader for ECCReader<R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzma::optimized_reader::SliceReader;

    #[test]
    fn test_ecc_reader_none_passthrough() {
        let test_data = b"Hello, World!";
        let slice_reader = SliceReader::new(test_data);
        let mut ecc_reader = ECCReader::new(slice_reader, ErrorCorrection::None, false);

        let mut output = vec![0u8; test_data.len()];
        let bytes_read = ecc_reader.read(&mut output).unwrap();

        assert_eq!(bytes_read, test_data.len());
        assert_eq!(&output, test_data);
    }
}
