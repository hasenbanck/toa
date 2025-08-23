use alloc::vec::Vec;

use crate::{
    ErrorCorrection, Result, Write,
    reed_solomon::{code_255_191, code_255_223, code_255_239},
};

type EncodeFunction<W> = fn(&mut ECCEncoder<W>, &[u8]) -> Result<()>;

fn encode_none<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<()> {
    encoder.inner.write_all(data)
}

fn encode_light<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<()> {
    encoder.encode_with_rs::<_, 239, 16>(data, code_255_239::encode)
}

fn encode_medium<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<()> {
    encoder.encode_with_rs::<_, 223, 32>(data, code_255_223::encode)
}

fn encode_heavy<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<()> {
    encoder.encode_with_rs::<_, 191, 64>(data, code_255_191::encode)
}

/// Error Correction Code Writer that applies Reed-Solomon encoding to compressed data.
pub(crate) struct ECCEncoder<W> {
    inner: W,
    encode_fn: EncodeFunction<W>,
    buffer: Vec<u8>,
    uses_buffer: bool,
}

impl<W: Write> ECCEncoder<W> {
    /// Create a new ECCWriter with the specified error correction level.
    pub(crate) fn new(inner: W, error_correction: ErrorCorrection) -> Self {
        let (encode_fn, uses_buffer) = match error_correction {
            ErrorCorrection::None => (encode_none as EncodeFunction<W>, false),
            ErrorCorrection::Light => (encode_light as EncodeFunction<W>, true),
            ErrorCorrection::Medium => (encode_medium as EncodeFunction<W>, true),
            ErrorCorrection::Heavy => (encode_heavy as EncodeFunction<W>, true),
        };

        Self {
            inner,
            encode_fn,
            buffer: Vec::new(),
            uses_buffer,
        }
    }

    fn encode_and_write_data(&mut self, data: &[u8]) -> Result<()> {
        (self.encode_fn)(self, data)
    }

    #[inline(always)]
    fn encode_with_rs<F, const DATA_LEN: usize, const PARITY_LEN: usize>(
        &mut self,
        data: &[u8],
        encode_rs_fn: F,
    ) -> Result<()>
    where
        F: Fn(&[u8; DATA_LEN]) -> [u8; PARITY_LEN],
    {
        if data.is_empty() {
            return Ok(());
        }

        let mut pos = 0;

        while pos < data.len() {
            let mut codeword_data = [0u8; DATA_LEN];
            let remaining_data = data.len() - pos;
            let actual_data_len = DATA_LEN.min(remaining_data);

            // Padding bytes come from the zero initialization.
            codeword_data[..actual_data_len].copy_from_slice(&data[pos..pos + actual_data_len]);

            pos += actual_data_len;

            let parity = encode_rs_fn(&codeword_data);

            self.inner.write_all(&codeword_data)?;
            self.inner.write_all(&parity)?;
        }

        Ok(())
    }

    /// Finish writing and flush any remaining data.
    pub(crate) fn finish(mut self) -> Result<W> {
        // Process any remaining data in the buffer
        if !self.buffer.is_empty() {
            let data = core::mem::take(&mut self.buffer);
            self.encode_and_write_data(&data)?;
        }

        Ok(self.inner)
    }
}

impl<W: Write> Write for ECCEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if !self.uses_buffer {
            return self.inner.write(buf);
        }

        self.buffer.extend_from_slice(buf);

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        if !self.uses_buffer {
            self.inner.flush()
        } else {
            // For RS modes, we need to wait for finish() to process the buffer.
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_ec_encoder_none_passthrough() {
        let mut output = Vec::new();
        let mut ec_encoder = ECCEncoder::new(&mut output, ErrorCorrection::None);

        let test_data = b"Hello, World!";
        ec_encoder.write_all(test_data).unwrap();

        let _final_output = ec_encoder.finish().unwrap();

        assert_eq!(output, test_data);
    }

    #[test]
    fn test_ec_encoder_light_encoding() {
        let mut output = Vec::new();
        let mut ec_encoder = ECCEncoder::new(&mut output, ErrorCorrection::Light);

        let test_data = b"Hello, Reed-Solomon encoding!";
        ec_encoder.write_all(test_data).unwrap();

        let _final_output = ec_encoder.finish().unwrap();

        assert_eq!(output.len(), 255);

        assert_eq!(&output[..test_data.len()], test_data);

        for (i, &x) in output[test_data.len()..239].iter().enumerate() {
            assert_eq!(x, 0, "Padding should be zero at position {i}");
        }

        assert_eq!(output[239..].len(), 16);
    }

    #[test]
    fn test_ec_encoder_multiple_codewords() {
        let mut output = Vec::new();
        let mut ec_encoder = ECCEncoder::new(&mut output, ErrorCorrection::Light);

        let mut test_data = Vec::new();
        test_data.extend_from_slice(b"A".repeat(300).as_slice());

        ec_encoder.write_all(&test_data).unwrap();
        let _final_output = ec_encoder.finish().unwrap();

        // We should have 2 codewords: 2 * 255 = 510 bytes.
        assert_eq!(output.len(), 2 * 255);

        assert_eq!(&output[..239], &test_data[0..239]);

        let second_codeword_data_size = 300 - 239;

        assert_eq!(
            &output[255..255 + second_codeword_data_size],
            &test_data[239..]
        );

        for (i, &x) in output[(255 + second_codeword_data_size)..(255 + 239)]
            .iter()
            .enumerate()
        {
            assert_eq!(x, 0, "Padding should be zero at position {i}");
        }
    }
}
