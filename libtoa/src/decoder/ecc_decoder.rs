use crate::{
    ErrorCorrection, Read, Result,
    circular_buffer::CircularBuffer,
    detect_ecc_simd_capability, error_invalid_data,
    reed_solomon::{code_255_191, code_255_223, code_255_239, primitives},
};

type DecodeSingleFunction<R> = fn(&mut ECCDecoder<R>, &mut [u8], usize) -> Result<usize>;
type DecodeBatchFunction<R> = fn(&mut ECCDecoder<R>, &mut [u8], usize) -> Result<usize>;

fn decode_single_none<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    _bytes_read: usize,
) -> Result<usize> {
    decoder.inner.read(buf)
}

fn decode_single_standard<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    decode_scalar_batch_with_rs(decoder, buf, bytes_read, code_255_239::decode)
}

fn decode_single_paranoid<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    decode_scalar_batch_with_rs(decoder, buf, bytes_read, code_255_223::decode)
}

fn decode_single_extreme<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    decode_scalar_batch_with_rs(decoder, buf, bytes_read, code_255_191::decode)
}

fn decode_scalar_batch_with_rs<R: Read, F>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
    decode_rs_fn: F,
) -> Result<usize>
where
    F: Fn(&mut [u8; 255]) -> Result<bool>,
{
    if buf.is_empty() || bytes_read == 0 {
        return Ok(0);
    }

    let aligned_buffer =
        &decoder.aligned_batch_buffer[decoder.aligned_offset..decoder.aligned_offset + bytes_read];

    // Calculate how many complete and partial codewords we have.
    let num_complete_codewords = bytes_read / 255;
    let partial_codeword_bytes = bytes_read % 255;
    let has_partial = partial_codeword_bytes > 0;
    let total_codewords = num_complete_codewords + if has_partial { 1 } else { 0 };

    let mut total_written = 0;
    let mut codeword_offset = 0;

    for codeword_idx in 0..total_codewords {
        if total_written >= buf.len() {
            panic!("Was batched even though there was not enough room");
        }

        let codeword_size = if codeword_idx < num_complete_codewords {
            255
        } else {
            partial_codeword_bytes
        };

        decoder.current_codeword[..codeword_size]
            .copy_from_slice(&aligned_buffer[codeword_offset..codeword_offset + codeword_size]);

        if codeword_size < 255 {
            decoder.current_codeword[codeword_size..].fill(0);
        }

        // Apply Reed-Solomon decoding if enabled.
        if decoder.validate_rs {
            let corrected = decode_rs_fn(&mut decoder.current_codeword).map_err(|_| {
                error_invalid_data("error correction couldn't correct a faulty block")
            })?;

            if corrected {
                eprintln!("Error correction corrected a faulty block");
            }
        }

        // Extract data portion - write directly to output buffer if possible.
        let data_slice = &decoder.current_codeword[..decoder.data_len];
        let write_len = (buf.len() - total_written).min(data_slice.len());

        buf[total_written..total_written + write_len].copy_from_slice(&data_slice[..write_len]);
        total_written += write_len;

        // If there's overflow, buffer it for next call..
        if write_len < data_slice.len() {
            // TODO: How can this happen? Why would we need to buffer something?
            //       Is maybe the padding the "problem" here we have to handel this way?
            decoder.buffer.append(&data_slice[write_len..]);
        }

        codeword_offset += 255;
    }

    Ok(total_written)
}

#[cfg(target_arch = "x86_64")]
fn decode_batch_standard_avx512<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    unsafe { decode_simd_batch_avx512::<R, 64, 239, 16>(decoder, buf, bytes_read) }
}

#[cfg(target_arch = "x86_64")]
fn decode_batch_paranoid_avx512<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    unsafe { decode_simd_batch_avx512::<R, 64, 223, 32>(decoder, buf, bytes_read) }
}

#[cfg(target_arch = "x86_64")]
fn decode_batch_extreme_avx512<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    unsafe { decode_simd_batch_avx512::<R, 64, 191, 64>(decoder, buf, bytes_read) }
}

#[cfg(target_arch = "x86_64")]
fn decode_batch_standard_avx2<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    unsafe { decode_simd_batch_avx2::<R, 32, 239, 16>(decoder, buf, bytes_read) }
}

#[cfg(target_arch = "x86_64")]
fn decode_batch_paranoid_avx2<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    unsafe { decode_simd_batch_avx2::<R, 32, 223, 32>(decoder, buf, bytes_read) }
}

#[cfg(target_arch = "x86_64")]
fn decode_batch_extreme_avx2<R: Read>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    unsafe { decode_simd_batch_avx2::<R, 32, 191, 64>(decoder, buf, bytes_read) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,gfni,avx512bw")]
unsafe fn decode_simd_batch_avx512<
    R: Read,
    const BATCH: usize,
    const DATA_LEN: usize,
    const PARITY_LEN: usize,
>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    use core::arch::x86_64::*;

    assert!(buf.len() >= BATCH * DATA_LEN);
    assert_eq!(bytes_read, BATCH * 255);

    // Get aligned batch buffer - exactly BATCH * 255 bytes.
    let aligned_buffer =
        &decoder.aligned_batch_buffer[decoder.aligned_offset..decoder.aligned_offset + bytes_read];

    // Convert aligned buffer to codewords using zero-copy alignment.
    let (prefix, aligned_codewords, _suffix) = unsafe { aligned_buffer.align_to::<[u8; 255]>() };
    assert!(prefix.is_empty());

    let batch_array: &[[u8; 255]; BATCH] = aligned_codewords[..BATCH]
        .try_into()
        .map_err(|_| error_invalid_data("batch slice conversion failed"))?;

    // Skip syndrome calculation entirely if validation is disabled.
    if !decoder.validate_rs {
        let mut written = 0;

        // Zero-copy path - direct access to aligned data.
        for codeword_idx in 0..BATCH {
            if written >= buf.len() {
                // Store remaining decoded data in buffer for next call.
                for remaining_idx in codeword_idx..BATCH {
                    decoder
                        .buffer
                        .append(&batch_array[remaining_idx][..DATA_LEN]);
                }
                break;
            }

            let data_slice = &batch_array[codeword_idx][..DATA_LEN];
            let write_len = buf[written..].len().min(data_slice.len());
            buf[written..written + write_len].copy_from_slice(&data_slice[..write_len]);
            written += write_len;

            if write_len < data_slice.len() {
                decoder.buffer.append(&data_slice[write_len..]);
            }
        }
        return Ok(written);
    }

    // Calculate syndromes for all codewords in parallel (only when validation is enabled).
    let transposed_codewords = crate::transpose_for_simd::<BATCH, 255>(batch_array);
    let mut syndromes_transposed = [[0u8; BATCH]; PARITY_LEN];

    // Calculate syndromes S_i = Σ(codeword[j] * α^(i*j)) for i=1..PARITY_LEN.
    for syndrome_idx in 0..PARITY_LEN {
        let mut syndrome_vec = _mm512_setzero_si512();

        for (byte_pos, byte_slice) in transposed_codewords.iter().enumerate() {
            let data_vec = unsafe { _mm512_loadu_si512(byte_slice.as_ptr() as *const __m512i) };

            // Calculate α^(syndrome_idx * byte_pos) for all positions.
            let power = ((syndrome_idx + 1) * byte_pos) % 255;
            let alpha_coefficient = primitives::gf_alpha_pow(power as isize);
            let alpha_vec = _mm512_set1_epi8(alpha_coefficient as i8);

            // Multiply data by α^power using GFNI.
            let product = _mm512_gf2p8mul_epi8(data_vec, alpha_vec);

            // Add to syndrome accumulator.
            syndrome_vec = _mm512_xor_si512(syndrome_vec, product);
        }

        unsafe {
            _mm512_storeu_si512(
                syndromes_transposed[syndrome_idx].as_mut_ptr() as *mut __m512i,
                syndrome_vec,
            );
        }
    }

    // Process each codeword based on its syndromes.
    let mut written = 0;

    for codeword_idx in 0..BATCH {
        if written >= buf.len() {
            panic!("Was batched even though there was not enough room");
        }

        // Check if this codeword has errors (any non-zero syndrome).
        let has_errors = syndromes_transposed
            .iter()
            .any(|syndrome_row| syndrome_row[codeword_idx] != 0);

        let data_slice = if has_errors && decoder.validate_rs {
            // Copy to batch_codewords for error correction.
            decoder.batch_codewords[codeword_idx] = batch_array[codeword_idx];

            // Fall back to scalar Reed-Solomon correction.
            let decode_fn = match PARITY_LEN {
                16 => code_255_239::decode,
                32 => code_255_223::decode,
                64 => code_255_191::decode,
                _ => return Err(error_invalid_data("unsupported parity length")),
            };

            let corrected =
                decode_fn(&mut decoder.batch_codewords[codeword_idx]).map_err(|_| {
                    error_invalid_data("error correction couldn't correct a faulty block")
                })?;

            if corrected {
                eprintln!("Error correction corrected a faulty block in SIMD batch");
            }

            // Use corrected data.
            &decoder.batch_codewords[codeword_idx][..DATA_LEN]
        } else {
            // Use zero-copy path for error-free codewords.
            &batch_array[codeword_idx][..DATA_LEN]
        };

        let write_len = buf[written..].len().min(data_slice.len());
        buf[written..written + write_len].copy_from_slice(&data_slice[..write_len]);
        written += write_len;

        if write_len < data_slice.len() {
            panic!("Was batched even though there was not enough room");
        }
    }

    Ok(written)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,gfni")]
unsafe fn decode_simd_batch_avx2<
    R: Read,
    const BATCH: usize,
    const DATA_LEN: usize,
    const PARITY_LEN: usize,
>(
    decoder: &mut ECCDecoder<R>,
    buf: &mut [u8],
    bytes_read: usize,
) -> Result<usize> {
    use core::arch::x86_64::*;

    assert!(buf.len() >= BATCH * DATA_LEN);
    assert_eq!(bytes_read, BATCH * 255);

    // Get aligned batch buffer - exactly BATCH * 255 bytes.
    let aligned_buffer =
        &decoder.aligned_batch_buffer[decoder.aligned_offset..decoder.aligned_offset + bytes_read];

    // Convert aligned buffer to codewords using zero-copy alignment.
    let (_prefix, aligned_codewords, _suffix) = unsafe { aligned_buffer.align_to::<[u8; 255]>() };

    let batch_array: &[[u8; 255]; BATCH] = aligned_codewords[..BATCH]
        .try_into()
        .map_err(|_| error_invalid_data("batch slice conversion failed"))?;

    // Skip syndrome calculation entirely if validation is disabled.
    if !decoder.validate_rs {
        let mut written = 0;

        // Zero-copy path - direct access to aligned data.
        for codeword_idx in 0..BATCH {
            if written >= buf.len() {
                panic!("Was batched even though there was not enough room");
            }

            let data_slice = &batch_array[codeword_idx][..DATA_LEN];
            let write_len = buf[written..].len().min(data_slice.len());
            buf[written..written + write_len].copy_from_slice(&data_slice[..write_len]);
            written += write_len;

            if write_len < data_slice.len() {
                decoder.buffer.append(&data_slice[write_len..]);
            }
        }
        return Ok(written);
    }

    // Calculate syndromes for all codewords in parallel (only when validation is enabled).
    let transposed_codewords = crate::transpose_for_simd::<BATCH, 255>(batch_array);
    let mut syndromes_transposed = [[0u8; BATCH]; PARITY_LEN];

    // Calculate syndromes S_i = Σ(codeword[j] * α^(i*j)) for i=1..PARITY_LEN.
    for syndrome_idx in 0..PARITY_LEN {
        let mut syndrome_vec = _mm256_setzero_si256();

        for (byte_pos, byte_slice) in transposed_codewords.iter().enumerate() {
            let data_vec = unsafe { _mm256_loadu_si256(byte_slice.as_ptr() as *const __m256i) };

            // Calculate α^(syndrome_idx * byte_pos) for all positions.
            let power = ((syndrome_idx + 1) * byte_pos) % 255;
            let alpha_coefficient = primitives::gf_alpha_pow(power as isize);
            let alpha_vec = _mm256_set1_epi8(alpha_coefficient as i8);

            // Multiply data by α^power using GFNI.
            let product = _mm256_gf2p8mul_epi8(data_vec, alpha_vec);

            // Add to syndrome accumulator.
            syndrome_vec = _mm256_xor_si256(syndrome_vec, product);
        }

        unsafe {
            _mm256_storeu_si256(
                syndromes_transposed[syndrome_idx].as_mut_ptr() as *mut __m256i,
                syndrome_vec,
            );
        }
    }

    // Process each codeword based on its syndromes.
    let mut written = 0;

    for codeword_idx in 0..BATCH {
        if written >= buf.len() {
            panic!("Was batched even though there was not enough room");
        }

        // Check if this codeword has errors (any non-zero syndrome).
        let has_errors = syndromes_transposed
            .iter()
            .any(|syndrome_row| syndrome_row[codeword_idx] != 0);

        let data_slice = if has_errors && decoder.validate_rs {
            // Copy to batch_codewords for error correction.
            decoder.batch_codewords[codeword_idx] = batch_array[codeword_idx];

            // Fall back to scalar Reed-Solomon correction
            let decode_fn = match PARITY_LEN {
                16 => code_255_239::decode,
                32 => code_255_223::decode,
                64 => code_255_191::decode,
                _ => return Err(error_invalid_data("unsupported parity length")),
            };

            let corrected =
                decode_fn(&mut decoder.batch_codewords[codeword_idx]).map_err(|_| {
                    error_invalid_data("error correction couldn't correct a faulty block")
                })?;

            if corrected {
                eprintln!("Error correction corrected a faulty block in SIMD batch");
            }

            // Use corrected data
            &decoder.batch_codewords[codeword_idx][..DATA_LEN]
        } else {
            // Use zero-copy path for error-free codewords
            &batch_array[codeword_idx][..DATA_LEN]
        };

        let write_len = buf[written..].len().min(data_slice.len());
        buf[written..written + write_len].copy_from_slice(&data_slice[..write_len]);
        written += write_len;

        if write_len < data_slice.len() {
            panic!("Was batched even though there was not enough room");
        }
    }

    Ok(written)
}

/// Error Correction Code Decoder that applies Reed-Solomon decoding to compressed data.
pub struct ECCDecoder<R> {
    inner: R,
    decode_single_fn: DecodeSingleFunction<R>,
    decode_batch_fn: Option<DecodeBatchFunction<R>>,
    buffer: CircularBuffer,
    batch_codewords: Vec<[u8; 255]>,
    current_codeword: [u8; 255],
    aligned_batch_buffer: Vec<u8>,
    aligned_offset: usize,
    uses_buffer: bool,
    validate_rs: bool,
    data_len: usize,
    _parity_len: usize,
    batch_size: usize,
}

impl<R: Read> ECCDecoder<R> {
    /// Create a new ECCDecoder with the specified error correction level.
    pub fn new(inner: R, error_correction: ErrorCorrection, validate_rs: bool) -> Self {
        let (use_simd, simd_batch_size) = detect_ecc_simd_capability();

        let (decode_single_fn, decode_batch_fn, uses_buffer, data_len, parity_len, batch_size) =
            match error_correction {
                ErrorCorrection::None => (
                    decode_single_none as DecodeSingleFunction<R>,
                    None,
                    false,
                    0,
                    0,
                    1,
                ),
                ErrorCorrection::Standard => (
                    decode_single_standard as DecodeSingleFunction<R>,
                    if use_simd && simd_batch_size == 64 {
                        Some(decode_batch_standard_avx512 as DecodeBatchFunction<R>)
                    } else if use_simd && simd_batch_size == 32 {
                        Some(decode_batch_standard_avx2 as DecodeBatchFunction<R>)
                    } else {
                        None
                    },
                    true,
                    239,
                    16,
                    if use_simd { simd_batch_size } else { 16 },
                ),
                ErrorCorrection::Paranoid => (
                    decode_single_paranoid as DecodeSingleFunction<R>,
                    if use_simd && simd_batch_size == 64 {
                        Some(decode_batch_paranoid_avx512 as DecodeBatchFunction<R>)
                    } else if use_simd && simd_batch_size == 32 {
                        Some(decode_batch_paranoid_avx2 as DecodeBatchFunction<R>)
                    } else {
                        None
                    },
                    true,
                    223,
                    32,
                    if use_simd { simd_batch_size } else { 16 },
                ),
                ErrorCorrection::Extreme => (
                    decode_single_extreme as DecodeSingleFunction<R>,
                    if use_simd && simd_batch_size == 64 {
                        Some(decode_batch_extreme_avx512 as DecodeBatchFunction<R>)
                    } else if use_simd && simd_batch_size == 32 {
                        Some(decode_batch_extreme_avx2 as DecodeBatchFunction<R>)
                    } else {
                        None
                    },
                    true,
                    191,
                    64,
                    if use_simd { simd_batch_size } else { 16 },
                ),
            };

        let buffer = if uses_buffer {
            CircularBuffer::with_capacity(batch_size * 255 * 2)
        } else {
            CircularBuffer::with_capacity(0)
        };

        let batch_codewords = vec![[0u8; 255]; batch_size];

        // Aligned batch buffer for efficient I/O - size for full batch plus alignment padding.
        let batch_bytes_size = batch_size * 255;
        let aligned_batch_buffer = vec![0u8; batch_bytes_size + 64];
        let aligned_offset = {
            let ptr = aligned_batch_buffer.as_ptr() as usize;
            let align_to = if use_simd { 64 } else { 1 }; // AVX512 alignment
            (align_to - (ptr % align_to)) % align_to
        };

        Self {
            inner,
            decode_single_fn,
            decode_batch_fn,
            buffer,
            batch_codewords,
            current_codeword: [0u8; 255],
            aligned_batch_buffer,
            aligned_offset,
            uses_buffer,
            validate_rs,
            data_len,
            _parity_len: parity_len,
            batch_size,
        }
    }

    fn decode(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0;

        // First serve any buffered data
        if self.buffer.available_data() > 0 {
            let copied = self.buffer.copy_to(&mut buf[written..]);
            self.buffer.consume(copied);
            written += copied;
            if written >= buf.len() {
                return Ok(written);
            }
        }

        while written < buf.len() {
            if let Some(decode_batch_fn) = self.decode_batch_fn {
                let remaining_space = buf.len() - written;

                // Batch processing if we have enough space in the output buffer for a full batch
                // worth of data.
                if remaining_space >= self.batch_size * self.data_len {
                    let batch_size_bytes = self.batch_size * 255;
                    let aligned_buffer = &mut self.aligned_batch_buffer
                        [self.aligned_offset..self.aligned_offset + batch_size_bytes];

                    let mut bytes_read = 0;

                    while bytes_read < batch_size_bytes {
                        match self.inner.read(&mut aligned_buffer[bytes_read..]) {
                            Ok(0) => break, // EOF
                            Ok(n) => bytes_read += n,
                            Err(e) => return Err(e),
                        }
                    }

                    if bytes_read == batch_size_bytes {
                        let batch_written = decode_batch_fn(self, &mut buf[written..], bytes_read)?;
                        written += batch_written;
                        continue;
                    } else if bytes_read == 0 {
                        // EOF
                        break;
                    }
                    // Fall through to single processing for partial batch or insufficient space.
                }
            }

            // Calculate how many codewords we can safely process based on output buffer space.
            let remaining_output_space = buf.len() - written;
            let max_codewords_for_output = if self.data_len > 0 {
                remaining_output_space.div_ceil(self.data_len)
            } else {
                panic!("ErrorCorrection::None should not call this function")
            };

            let codewords_to_read = max_codewords_for_output.min(self.batch_size).max(1);
            let bytes_to_read = codewords_to_read * 255;

            let aligned_buffer = &mut self.aligned_batch_buffer
                [self.aligned_offset..self.aligned_offset + bytes_to_read];

            let mut bytes_read = 0;

            while bytes_read < bytes_to_read {
                match self.inner.read(&mut aligned_buffer[bytes_read..]) {
                    Ok(0) => {
                        // EOF
                        if bytes_read == 0 {
                            return Ok(written);
                        }
                        break;
                    }
                    Ok(n) => {
                        bytes_read += n;
                    }
                    Err(e) => return Err(e),
                }
            }

            if bytes_read == 0 {
                // EOF
                break;
            }

            let single_written = (self.decode_single_fn)(self, &mut buf[written..], bytes_read)?;
            if single_written == 0 {
                // EOF or no progress.
                break;
            }

            written += single_written;
        }

        Ok(written)
    }

    /// Get the inner decoder.
    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for ECCDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.uses_buffer {
            return self.inner.read(buf);
        }

        self.decode(buf)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::{Write, encoder::ECCEncoder, tests::Lcg};

    #[test]
    fn test_ecc_decoder_none_passthrough() {
        let test_data = b"Hello, World!";
        let mut ecc_decoder = ECCDecoder::new(test_data.as_slice(), ErrorCorrection::None, false);

        let mut output = vec![0u8; test_data.len()];
        let bytes_read = ecc_decoder.read(&mut output).unwrap();

        assert_eq!(bytes_read, test_data.len());
        assert_eq!(&output, test_data);
    }

    fn test_ecc_decoder_roundtrip_with_level(error_correction: ErrorCorrection, seed: u64) {
        const TEST_DATA_SIZE: usize = 2 * 1024 * 1024;

        let mut lcg = Lcg::new(seed);
        let mut test_data = vec![0u8; TEST_DATA_SIZE];
        lcg.fill_buffer(&mut test_data);

        let mut encoded_output = Vec::new();
        let mut ecc_encoder = ECCEncoder::new(&mut encoded_output, error_correction);
        ecc_encoder.write_all(&test_data).unwrap();
        ecc_encoder.finish().unwrap();

        let mut ecc_decoder = ECCDecoder::new(encoded_output.as_slice(), error_correction, false);
        let mut decoded_output = Vec::new();

        let mut temp_buf = [0u8; 4096];
        loop {
            let bytes_read = ecc_decoder.read(&mut temp_buf).unwrap();
            if bytes_read == 0 {
                break;
            }
            decoded_output.extend_from_slice(&temp_buf[..bytes_read]);
        }

        assert!(decoded_output.len() >= test_data.len());
        decoded_output.truncate(test_data.len());

        assert_eq!(blake3::hash(&test_data), blake3::hash(&decoded_output));
    }

    #[test]
    fn test_ecc_decoder_standard_roundtrip() {
        test_ecc_decoder_roundtrip_with_level(ErrorCorrection::Standard, 0x123456789ABCDEF0);
    }

    #[test]
    fn test_ecc_decoder_paranoid_roundtrip() {
        test_ecc_decoder_roundtrip_with_level(ErrorCorrection::Paranoid, 0xFEDCBA9876543210);
    }

    #[test]
    fn test_ecc_decoder_extreme_roundtrip() {
        test_ecc_decoder_roundtrip_with_level(ErrorCorrection::Extreme, 0xABCDEF0123456789);
    }
}
