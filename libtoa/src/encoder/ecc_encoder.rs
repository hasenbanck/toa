#[cfg(target_arch = "x86_64")]
use crate::reed_solomon::get_generator_poly;
use crate::{
    ErrorCorrection, Result, SimdOverride, Write,
    circular_buffer::CircularBuffer,
    reed_solomon::{code_255_191, code_255_223, code_255_239},
};

#[cfg(target_arch = "x86_64")]
const ECC_BATCH_SIZE_AVX: usize = 32;

#[cfg(target_arch = "x86_64")]
const ECC_BATCH_SIZE_SSE: usize = 16;

#[cfg(target_arch = "aarch64")]
const ECC_BATCH_SIZE_NEON: usize = 16;

type EncodeFunction<W> = fn(&mut ECCEncoder<W>, &[u8]) -> Result<usize>;

fn encode_none<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    encoder.inner.write_all(data)?;
    Ok(data.len())
}

fn encode_standard<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    encoder.encode_scalar::<_, 239, 16>(data, code_255_239::encode)
}

fn encode_paranoid<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    encoder.encode_scalar::<_, 223, 32>(data, code_255_223::encode)
}

fn encode_extreme<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    encoder.encode_scalar::<_, 191, 64>(data, code_255_191::encode)
}

#[cfg(target_arch = "x86_64")]
fn encode_standard_sse2_gfni<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 239, 16>(data, |writer, batch_codewords| {
            encode_simd_batch_sse2_gfni::<_, 16, 239, 16>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_paranoid_sse2_gfni<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 223, 32>(data, |writer, batch_codewords| {
            encode_simd_batch_sse2_gfni::<_, 16, 223, 32>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_extreme_sse2_gfni<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 191, 64>(data, |writer, batch_codewords| {
            encode_simd_batch_sse2_gfni::<_, 16, 191, 64>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_standard_ssse3<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 239, 16>(data, |writer, batch_codewords| {
            encode_simd_batch_ssse3::<_, 16, 239, 16>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_paranoid_ssse3<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 223, 32>(data, |writer, batch_codewords| {
            encode_simd_batch_ssse3::<_, 16, 223, 32>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_extreme_ssse3<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 191, 64>(data, |writer, batch_codewords| {
            encode_simd_batch_ssse3::<_, 16, 191, 64>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_standard_avx2<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 32, 239, 16>(data, |writer, batch_codewords| {
            encode_simd_batch_avx2::<_, 32, 239, 16>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_paranoid_avx2<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 32, 223, 32>(data, |writer, batch_codewords| {
            encode_simd_batch_avx2::<_, 32, 223, 32>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_extreme_avx2<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 32, 191, 64>(data, |writer, batch_codewords| {
            encode_simd_batch_avx2::<_, 32, 191, 64>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_standard_avx2_gfni<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 32, 239, 16>(data, |writer, batch_codewords| {
            encode_simd_batch_avx2_gfni::<_, 32, 239, 16>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_paranoid_avx2_gfni<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 32, 223, 32>(data, |writer, batch_codewords| {
            encode_simd_batch_avx2_gfni::<_, 32, 223, 32>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn encode_extreme_avx2_gfni<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 32, 191, 64>(data, |writer, batch_codewords| {
            encode_simd_batch_avx2_gfni::<_, 32, 191, 64>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "aarch64")]
fn encode_standard_neon<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 239, 16>(data, |writer, batch_codewords| {
            encode_simd_batch_neon::<_, 16, 239, 16>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "aarch64")]
fn encode_paranoid_neon<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 223, 32>(data, |writer, batch_codewords| {
            encode_simd_batch_neon::<_, 16, 223, 32>(writer, batch_codewords)
        })
    }
}

#[cfg(target_arch = "aarch64")]
fn encode_extreme_neon<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe {
        encoder.encode_batch::<_, 16, 191, 64>(data, |writer, batch_codewords| {
            encode_simd_batch_neon::<_, 16, 191, 64>(writer, batch_codewords)
        })
    }
}

/// Error Correction Code Writer that applies Reed-Solomon encoding to compressed data.
pub struct ECCEncoder<W> {
    inner: W,
    encode_fn: EncodeFunction<W>,
    encode_fn_simd: Option<EncodeFunction<W>>,
    buffer: CircularBuffer,
    uses_buffer: bool,
    batch_size: usize,
}

impl<W: Write> ECCEncoder<W> {
    #[cfg(target_arch = "x86_64")]
    fn get_simd_function(error_correction: ErrorCorrection) -> (Option<EncodeFunction<W>>, usize) {
        match error_correction {
            ErrorCorrection::None => (None, 1),
            ErrorCorrection::Standard => {
                if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_standard_avx2_gfni as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX,
                    )
                } else if is_x86_feature_detected!("avx2") {
                    (
                        Some(encode_standard_avx2 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX,
                    )
                } else if is_x86_feature_detected!("sse2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_standard_sse2_gfni as EncodeFunction<W>),
                        ECC_BATCH_SIZE_SSE,
                    )
                } else if is_x86_feature_detected!("ssse3") {
                    (
                        Some(encode_standard_ssse3 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_SSE,
                    )
                } else {
                    (None, 1)
                }
            }
            ErrorCorrection::Paranoid => {
                if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_paranoid_avx2_gfni as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX,
                    )
                } else if is_x86_feature_detected!("avx2") {
                    (
                        Some(encode_paranoid_avx2 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX,
                    )
                } else if is_x86_feature_detected!("sse2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_paranoid_sse2_gfni as EncodeFunction<W>),
                        ECC_BATCH_SIZE_SSE,
                    )
                } else if is_x86_feature_detected!("ssse3") {
                    (
                        Some(encode_paranoid_ssse3 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_SSE,
                    )
                } else {
                    (None, 1)
                }
            }
            ErrorCorrection::Extreme => {
                if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_extreme_avx2_gfni as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX,
                    )
                } else if is_x86_feature_detected!("avx2") {
                    (
                        Some(encode_extreme_avx2 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX,
                    )
                } else if is_x86_feature_detected!("sse2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_extreme_sse2_gfni as EncodeFunction<W>),
                        ECC_BATCH_SIZE_SSE,
                    )
                } else if is_x86_feature_detected!("ssse3") {
                    (
                        Some(encode_extreme_ssse3 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_SSE,
                    )
                } else {
                    (None, 1)
                }
            }
        }
    }

    #[cfg(all(feature = "std", target_arch = "aarch64"))]
    fn get_simd_function(error_correction: ErrorCorrection) -> (Option<EncodeFunction<W>>, usize) {
        use std::arch::is_aarch64_feature_detected;

        match error_correction {
            ErrorCorrection::None => (None, 1),
            ErrorCorrection::Standard => {
                if is_aarch64_feature_detected!("neon") {
                    (
                        Some(encode_standard_neon as EncodeFunction<W>),
                        ECC_BATCH_SIZE_NEON,
                    )
                } else {
                    (None, 1)
                }
            }
            ErrorCorrection::Paranoid => {
                if is_aarch64_feature_detected!("neon") {
                    (
                        Some(encode_paranoid_neon as EncodeFunction<W>),
                        ECC_BATCH_SIZE_NEON,
                    )
                } else {
                    (None, 1)
                }
            }
            ErrorCorrection::Extreme => {
                if is_aarch64_feature_detected!("neon") {
                    (
                        Some(encode_extreme_neon as EncodeFunction<W>),
                        ECC_BATCH_SIZE_NEON,
                    )
                } else {
                    (None, 1)
                }
            }
        }
    }

    #[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", feature = "std"))))]
    fn get_simd_function(_error_correction: ErrorCorrection) -> (Option<EncodeFunction<W>>, usize) {
        (None, 1)
    }

    fn apply_simd_override(
        error_correction: ErrorCorrection,
        override_setting: SimdOverride,
    ) -> (Option<EncodeFunction<W>>, usize) {
        match override_setting {
            SimdOverride::Auto => Self::get_simd_function(error_correction),
            SimdOverride::ForceScalar => (None, 1),
            #[cfg(target_arch = "x86_64")]
            SimdOverride::ForceSsse3 => {
                if is_x86_feature_detected!("ssse3") {
                    match error_correction {
                        ErrorCorrection::None => (None, 1),
                        ErrorCorrection::Standard => (
                            Some(encode_standard_ssse3 as EncodeFunction<W>),
                            ECC_BATCH_SIZE_SSE,
                        ),
                        ErrorCorrection::Paranoid => (
                            Some(encode_paranoid_ssse3 as EncodeFunction<W>),
                            ECC_BATCH_SIZE_SSE,
                        ),
                        ErrorCorrection::Extreme => (
                            Some(encode_extreme_ssse3 as EncodeFunction<W>),
                            ECC_BATCH_SIZE_SSE,
                        ),
                    }
                } else {
                    eprintln!("Warning: SSSE3 requested but not available, falling back to scalar");
                    (None, 1)
                }
            }
            #[cfg(target_arch = "x86_64")]
            SimdOverride::ForceSse2Gfni => {
                if is_x86_feature_detected!("ssse3") && is_x86_feature_detected!("gfni") {
                    match error_correction {
                        ErrorCorrection::None => (None, 1),
                        ErrorCorrection::Standard => (
                            Some(encode_standard_sse2_gfni as EncodeFunction<W>),
                            ECC_BATCH_SIZE_SSE,
                        ),
                        ErrorCorrection::Paranoid => (
                            Some(encode_paranoid_sse2_gfni as EncodeFunction<W>),
                            ECC_BATCH_SIZE_SSE,
                        ),
                        ErrorCorrection::Extreme => (
                            Some(encode_extreme_sse2_gfni as EncodeFunction<W>),
                            ECC_BATCH_SIZE_SSE,
                        ),
                    }
                } else {
                    eprintln!(
                        "Warning: SSSE3+GFNI requested but not available, falling back to scalar"
                    );
                    (None, 1)
                }
            }
            #[cfg(target_arch = "x86_64")]
            SimdOverride::ForceAvx2 => {
                if is_x86_feature_detected!("avx2") {
                    match error_correction {
                        ErrorCorrection::None => (None, 1),
                        ErrorCorrection::Standard => (
                            Some(encode_standard_avx2 as EncodeFunction<W>),
                            ECC_BATCH_SIZE_AVX,
                        ),
                        ErrorCorrection::Paranoid => (
                            Some(encode_paranoid_avx2 as EncodeFunction<W>),
                            ECC_BATCH_SIZE_AVX,
                        ),
                        ErrorCorrection::Extreme => (
                            Some(encode_extreme_avx2 as EncodeFunction<W>),
                            ECC_BATCH_SIZE_AVX,
                        ),
                    }
                } else {
                    eprintln!("Warning: AVX2 requested but not available, falling back to scalar");
                    (None, 1)
                }
            }
            #[cfg(target_arch = "x86_64")]
            SimdOverride::ForceAvx2Gfni => {
                if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("gfni") {
                    match error_correction {
                        ErrorCorrection::None => (None, 1),
                        ErrorCorrection::Standard => (
                            Some(encode_standard_avx2_gfni as EncodeFunction<W>),
                            ECC_BATCH_SIZE_AVX,
                        ),
                        ErrorCorrection::Paranoid => (
                            Some(encode_paranoid_avx2_gfni as EncodeFunction<W>),
                            ECC_BATCH_SIZE_AVX,
                        ),
                        ErrorCorrection::Extreme => (
                            Some(encode_extreme_avx2_gfni as EncodeFunction<W>),
                            ECC_BATCH_SIZE_AVX,
                        ),
                    }
                } else {
                    eprintln!(
                        "Warning: AVX2+GFNI requested but not available, falling back to scalar"
                    );
                    (None, 1)
                }
            }
            #[cfg(target_arch = "aarch64")]
            SimdOverride::ForceNeon => {
                #[cfg(feature = "std")]
                {
                    if std::arch::is_aarch64_feature_detected!("neon") {
                        match error_correction {
                            ErrorCorrection::None => (None, 1),
                            ErrorCorrection::Standard => (
                                Some(encode_standard_neon as EncodeFunction<W>),
                                ECC_BATCH_SIZE_NEON,
                            ),
                            ErrorCorrection::Paranoid => (
                                Some(encode_paranoid_neon as EncodeFunction<W>),
                                ECC_BATCH_SIZE_NEON,
                            ),
                            ErrorCorrection::Extreme => (
                                Some(encode_extreme_neon as EncodeFunction<W>),
                                ECC_BATCH_SIZE_NEON,
                            ),
                        }
                    } else {
                        eprintln!(
                            "Warning: NEON requested but not available, falling back to scalar"
                        );
                        (None, 1)
                    }
                }
                #[cfg(not(feature = "std"))]
                {
                    eprintln!(
                        "Warning: NEON detection not available in no_std, falling back to scalar"
                    );
                    (None, 1)
                }
            }
        }
    }

    /// Create a new ECCWriter with the specified error correction level and SIMD override.
    pub fn new(inner: W, error_correction: ErrorCorrection, simd_override: SimdOverride) -> Self {
        let (encode_fn_simd, simd_batch_size) =
            Self::apply_simd_override(error_correction, simd_override);

        let (encode_fn, uses_buffer, codeword_data_len) = match error_correction {
            ErrorCorrection::None => (encode_none as EncodeFunction<W>, false, 0),
            ErrorCorrection::Standard => (encode_standard as EncodeFunction<W>, true, 239),
            ErrorCorrection::Paranoid => (encode_paranoid as EncodeFunction<W>, true, 223),
            ErrorCorrection::Extreme => (encode_extreme as EncodeFunction<W>, true, 191),
        };

        let batch_size = if encode_fn_simd.is_some() {
            simd_batch_size * codeword_data_len
        } else {
            codeword_data_len
        };

        let buffer = if uses_buffer {
            CircularBuffer::with_capacity(batch_size * 2)
        } else {
            CircularBuffer::with_capacity(0)
        };

        Self {
            inner,
            encode_fn,
            encode_fn_simd,
            buffer,
            uses_buffer,
            batch_size,
        }
    }

    fn encode_and_write_data(&mut self, data: &[u8]) -> Result<usize> {
        if let Some(simd_fn) = self.encode_fn_simd {
            simd_fn(self, data)
        } else {
            (self.encode_fn)(self, data)
        }
    }

    #[inline(always)]
    fn encode_scalar<F, const DATA_LEN: usize, const PARITY_LEN: usize>(
        &mut self,
        data: &[u8],
        encode_rs_fn: F,
    ) -> Result<usize>
    where
        F: Fn(&[u8; DATA_LEN]) -> [u8; PARITY_LEN],
    {
        let mut input_processed = 0;

        while self.buffer.available_data() >= DATA_LEN
            || (data.is_empty() && self.buffer.available_data() > 0)
        {
            let mut codeword_data = [0u8; DATA_LEN];
            let copied = self.buffer.copy_to(&mut codeword_data);

            // Zero-padding is already in place from initialization.
            let parity = encode_rs_fn(&codeword_data);
            self.inner.write_all(&codeword_data)?;
            self.inner.write_all(&parity)?;

            self.buffer.consume(copied.min(DATA_LEN));

            if copied < DATA_LEN {
                break;
            }
        }

        if data.is_empty() {
            return Ok(0);
        }

        let mut pos = 0;
        while pos + DATA_LEN <= data.len() {
            let mut codeword_data = [0u8; DATA_LEN];
            codeword_data.copy_from_slice(&data[pos..pos + DATA_LEN]);

            let parity = encode_rs_fn(&codeword_data);
            self.inner.write_all(&codeword_data)?;
            self.inner.write_all(&parity)?;

            pos += DATA_LEN;
            input_processed += DATA_LEN;
        }

        Ok(input_processed)
    }

    unsafe fn encode_batch<F, const BATCH: usize, const DATA_LEN: usize, const PARITY_LEN: usize>(
        &mut self,
        data: &[u8],
        simd_encode_fn: F,
    ) -> Result<usize>
    where
        F: Fn(&mut W, &[[u8; DATA_LEN]; BATCH]) -> Result<()>,
    {
        let batch_data_size = BATCH * DATA_LEN;
        let mut input_processed = 0;

        if self.buffer.available_data() >= batch_data_size {
            let mut batch_codewords = [[0u8; DATA_LEN]; BATCH];

            if self
                .buffer
                .fill_batch_from_buffer::<BATCH, DATA_LEN>(&mut batch_codewords, batch_data_size)
            {
                simd_encode_fn(&mut self.inner, &batch_codewords)?;

                self.buffer.consume(batch_data_size);
                return Ok(0);
            }
        }

        // Try to process aligned data directly without copying.
        let (left, aligned, _right) = unsafe { data.align_to::<[u8; DATA_LEN]>() };

        if left.is_empty() && aligned.len() >= BATCH {
            // Data is perfectly aligned, and we have enough for at least one batch!
            let batches_possible = aligned.len() / BATCH;

            for batch_idx in 0..batches_possible {
                let batch_start = batch_idx * BATCH;
                let batch_slice = &aligned[batch_start..batch_start + BATCH];

                // Safe transmute: we know the slice has exactly BATCH elements of [u8; DATA_LEN]
                let batch_codewords: &[[u8; DATA_LEN]; BATCH] =
                    unsafe { &*(batch_slice.as_ptr() as *const [[u8; DATA_LEN]; BATCH]) };

                simd_encode_fn(&mut self.inner, batch_codewords)?;

                input_processed += batch_data_size;
            }

            return Ok(input_processed);
        }

        // Fallback to copying approach for misaligned or insufficient data.
        let mut pos = 0;
        while pos + batch_data_size <= data.len() {
            let mut batch_codewords = [[0u8; DATA_LEN]; BATCH];

            for (i, codeword) in batch_codewords.iter_mut().enumerate() {
                let start = pos + i * DATA_LEN;
                let end = start + DATA_LEN;
                codeword.copy_from_slice(&data[start..end]);
            }

            simd_encode_fn(&mut self.inner, &batch_codewords)?;

            pos += batch_data_size;
            input_processed += batch_data_size;
        }

        Ok(input_processed)
    }

    /// Finish writing and flush any remaining data.
    pub fn finish(mut self) -> Result<W> {
        if self.buffer.available_data() > 0 {
            // Process remaining buffered data.
            (self.encode_fn)(&mut self, &[])?;
        }

        Ok(self.inner)
    }
}

impl<W: Write> Write for ECCEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if !self.uses_buffer {
            return self.inner.write(buf);
        }

        if buf.is_empty() {
            return Ok(0);
        }

        let mut buf_pos = 0;

        // If we have buffered data, try to fill it to a processable amount.
        if self.buffer.available_data() > 0 {
            let needed = self.batch_size - self.buffer.available_data();
            let available = buf.len().min(needed);

            self.buffer.append(&buf[..available]);
            buf_pos += available;

            // Try to process the buffer if it's full enough, else return.
            match self.buffer.available_data() >= self.batch_size {
                true => {
                    self.encode_and_write_data(&[])?;
                }
                false => {
                    // Not enough data to encode yet.
                    return Ok(available);
                }
            }
        }

        let remaining = buf.len() - buf_pos;

        if remaining >= self.batch_size {
            // We have enough for a complete batch, process directly.
            let processed = self.encode_and_write_data(&buf[buf_pos..])?;
            if buf_pos + processed < buf.len() {
                self.buffer.append(&buf[buf_pos + processed..]);
            }
        } else {
            // Not enough for a complete batch, store in buffer.
            if remaining > 0 {
                self.buffer.append(&buf[buf_pos..]);
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,gfni")]
unsafe fn encode_simd_batch_avx2_gfni<
    R: Write,
    const BATCH: usize,
    const DATA_LEN: usize,
    const PARITY_LEN: usize,
>(
    mut writer: R,
    batch_codewords: &[[u8; DATA_LEN]; BATCH],
) -> Result<()> {
    use core::arch::x86_64::*;

    let transposed_data = crate::transpose_for_simd::<BATCH, DATA_LEN>(batch_codewords);
    let gen_poly = get_generator_poly::<PARITY_LEN>();

    // LFSR-based encoding with SIMD.
    let mut remainder = [[0u8; BATCH]; PARITY_LEN];

    // Process each data byte position (from highest to lowest).
    for data_bytes in transposed_data.iter().rev() {
        let data_ptr = data_bytes.as_ptr() as *const __m256i;
        let data_vec = unsafe { _mm256_loadu_si256(data_ptr) };

        // XOR with feedback from the highest remainder position.
        let feedback_ptr = remainder[PARITY_LEN - 1].as_ptr() as *const __m256i;
        let feedback_vec = unsafe { _mm256_loadu_si256(feedback_ptr) };
        let feedback = _mm256_xor_si256(data_vec, feedback_vec);

        // Shift remainder right.
        for i in (1..PARITY_LEN).rev() {
            remainder[i] = remainder[i - 1];
        }
        remainder[0] = [0u8; BATCH];

        // Apply generator polynomial multiplication with GFNI.
        for (i, &g_coeff) in gen_poly[..PARITY_LEN].iter().enumerate() {
            if g_coeff != 0 {
                let g_vec = _mm256_set1_epi8(g_coeff as i8);
                let product = _mm256_gf2p8mul_epi8(feedback, g_vec);

                let current_ptr = remainder[i].as_ptr() as *const __m256i;
                let current = unsafe { _mm256_loadu_si256(current_ptr) };
                let result = _mm256_xor_si256(current, product);
                let result_ptr = remainder[i].as_mut_ptr() as *mut __m256i;
                unsafe { _mm256_storeu_si256(result_ptr, result) };
            }
        }
    }

    let (data_codewords, parity_codewords) =
        crate::transpose_from_simd::<BATCH, DATA_LEN, PARITY_LEN>(&transposed_data, &remainder);

    for i in 0..BATCH {
        writer.write_all(&data_codewords[i])?;
        writer.write_all(&parity_codewords[i])?;
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx,avx2")]
unsafe fn encode_simd_batch_avx2<
    R: Write,
    const BATCH: usize,
    const DATA_LEN: usize,
    const PARITY_LEN: usize,
>(
    mut writer: R,
    batch_codewords: &[[u8; DATA_LEN]; BATCH],
) -> Result<()> {
    use core::arch::x86_64::*;

    use crate::reed_solomon::simd::{RS_255_191_TABLES, RS_255_223_TABLES, RS_255_239_TABLES};

    // Define a macro to reduce repetition in applying tables.
    macro_rules! apply_tables_for_parity {
        ($parity:expr, $tables:expr, $table_len:expr, $feedback:expr, $remainder:expr) => {
            for i in 0..$parity {
                if i < $table_len {
                    let table = &$tables[0][i];
                    unsafe {
                        apply_avx2_gf_multiplication::<BATCH>($feedback, &mut $remainder[i], table);
                    }
                }
            }
        };
    }

    let transposed_data = crate::transpose_for_simd::<BATCH, DATA_LEN>(batch_codewords);

    // LFSR-based encoding with SIMD and lookup tables.
    let mut remainder = [[0u8; BATCH]; PARITY_LEN];

    // Process each data byte position (from highest to lowest).
    for data_bytes in transposed_data.iter().rev() {
        let data_ptr = data_bytes.as_ptr() as *const __m256i;
        let data_vec = unsafe { _mm256_loadu_si256(data_ptr) };

        // XOR with feedback from the highest remainder position.
        let feedback_ptr = remainder[PARITY_LEN - 1].as_ptr() as *const __m256i;
        let feedback_vec = unsafe { _mm256_loadu_si256(feedback_ptr) };
        let feedback = _mm256_xor_si256(data_vec, feedback_vec);

        // Shift remainder right.
        for i in (1..PARITY_LEN).rev() {
            remainder[i] = remainder[i - 1];
        }
        remainder[0] = [0u8; BATCH];

        // Apply generator polynomial multiplication using lookup tables.
        match PARITY_LEN {
            16 => apply_tables_for_parity!(PARITY_LEN, RS_255_239_TABLES, 17, &feedback, remainder),
            32 => apply_tables_for_parity!(PARITY_LEN, RS_255_223_TABLES, 33, &feedback, remainder),
            64 => apply_tables_for_parity!(PARITY_LEN, RS_255_191_TABLES, 65, &feedback, remainder),
            _ => unreachable!(),
        }
    }

    let (data_codewords, parity_codewords) =
        crate::transpose_from_simd::<BATCH, DATA_LEN, PARITY_LEN>(&transposed_data, &remainder);

    for i in 0..BATCH {
        writer.write_all(&data_codewords[i])?;
        writer.write_all(&parity_codewords[i])?;
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx,avx2")]
unsafe fn apply_avx2_gf_multiplication<const BATCH: usize>(
    feedback: &core::arch::x86_64::__m256i,
    remainder_row: &mut [u8; BATCH],
    table: &crate::reed_solomon::simd::GfFourBitTables,
) {
    use core::arch::x86_64::*;

    // Extract low and high nibbles from feedback vector.
    let low_nibble_mask = _mm256_set1_epi8(0x0F_u8 as i8);
    let low_nibbles = _mm256_and_si256(*feedback, low_nibble_mask);
    let high_nibbles = _mm256_srli_epi16::<4>(*feedback);
    let high_nibbles = _mm256_and_si256(high_nibbles, low_nibble_mask);

    // Perform table lookups for low nibbles.
    // Note: We need to duplicate the 16-byte table to fill the 32-byte AVX2 register.
    let low_table_ptr = table.low_four.as_ptr() as *const __m128i;
    let low_table_128 = unsafe { _mm_loadu_si128(low_table_ptr) };
    let low_table = _mm256_broadcastsi128_si256(low_table_128);
    let low_products = _mm256_shuffle_epi8(low_table, low_nibbles);

    // Perform table lookups for high nibbles.
    let high_table_ptr = table.high_four.as_ptr() as *const __m128i;
    let high_table_128 = unsafe { _mm_loadu_si128(high_table_ptr) };
    let high_table = _mm256_broadcastsi128_si256(high_table_128);
    let high_products = _mm256_shuffle_epi8(high_table, high_nibbles);

    // Combine low and high products.
    let products = _mm256_xor_si256(low_products, high_products);

    // XOR with current remainder.
    let current_ptr = remainder_row.as_ptr() as *const __m256i;
    let current = unsafe { _mm256_loadu_si256(current_ptr) };
    let result = _mm256_xor_si256(current, products);
    let result_ptr = remainder_row.as_mut_ptr() as *mut __m256i;
    unsafe { _mm256_storeu_si256(result_ptr, result) };
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,gfni")]
unsafe fn encode_simd_batch_sse2_gfni<
    R: Write,
    const BATCH: usize,
    const DATA_LEN: usize,
    const PARITY_LEN: usize,
>(
    mut writer: R,
    batch_codewords: &[[u8; DATA_LEN]; BATCH],
) -> Result<()> {
    use core::arch::x86_64::*;

    let transposed_data = crate::transpose_for_simd::<BATCH, DATA_LEN>(batch_codewords);
    let gen_poly = get_generator_poly::<PARITY_LEN>();

    // LFSR-based encoding with SIMD.
    let mut remainder = [[0u8; BATCH]; PARITY_LEN];

    // Process each data byte position (from highest to lowest).
    for data_bytes in transposed_data.iter().rev() {
        let data_ptr = data_bytes.as_ptr() as *const __m128i;
        let data_vec = unsafe { _mm_loadu_si128(data_ptr) };

        // XOR with feedback from the highest remainder position.
        let feedback_ptr = remainder[PARITY_LEN - 1].as_ptr() as *const __m128i;
        let feedback_vec = unsafe { _mm_loadu_si128(feedback_ptr) };
        let feedback = _mm_xor_si128(data_vec, feedback_vec);

        // Shift remainder right.
        for i in (1..PARITY_LEN).rev() {
            remainder[i] = remainder[i - 1];
        }
        remainder[0] = [0u8; BATCH];

        // Apply generator polynomial multiplication with GFNI.
        for (i, &g_coeff) in gen_poly[..PARITY_LEN].iter().enumerate() {
            if g_coeff != 0 {
                let g_vec = _mm_set1_epi8(g_coeff as i8);
                let product = _mm_gf2p8mul_epi8(feedback, g_vec);

                let current_ptr = remainder[i].as_ptr() as *const __m128i;
                let current = unsafe { _mm_loadu_si128(current_ptr) };
                let result = _mm_xor_si128(current, product);
                let result_ptr = remainder[i].as_mut_ptr() as *mut __m128i;
                unsafe { _mm_storeu_si128(result_ptr, result) };
            }
        }
    }

    let (data_codewords, parity_codewords) =
        crate::transpose_from_simd::<BATCH, DATA_LEN, PARITY_LEN>(&transposed_data, &remainder);

    for i in 0..BATCH {
        writer.write_all(&data_codewords[i])?;
        writer.write_all(&parity_codewords[i])?;
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,ssse3")]
unsafe fn encode_simd_batch_ssse3<
    R: Write,
    const BATCH: usize,
    const DATA_LEN: usize,
    const PARITY_LEN: usize,
>(
    mut writer: R,
    batch_codewords: &[[u8; DATA_LEN]; BATCH],
) -> Result<()> {
    use core::arch::x86_64::*;

    use crate::reed_solomon::simd::{RS_255_191_TABLES, RS_255_223_TABLES, RS_255_239_TABLES};

    // Define a macro to reduce repetition in applying tables.
    macro_rules! apply_tables_for_parity {
        ($parity:expr, $tables:expr, $table_len:expr, $feedback:expr, $remainder:expr) => {
            for i in 0..$parity {
                if i < $table_len {
                    let table = &$tables[0][i];
                    unsafe {
                        apply_ssse3_gf_multiplication::<BATCH>(
                            $feedback,
                            &mut $remainder[i],
                            table,
                        );
                    }
                }
            }
        };
    }

    let transposed_data = crate::transpose_for_simd::<BATCH, DATA_LEN>(batch_codewords);

    // LFSR-based encoding with SIMD and lookup tables.
    let mut remainder = [[0u8; BATCH]; PARITY_LEN];

    // Process each data byte position (from highest to lowest).
    for data_bytes in transposed_data.iter().rev() {
        let data_ptr = data_bytes.as_ptr() as *const __m128i;
        let data_vec = unsafe { _mm_loadu_si128(data_ptr) };

        // XOR with feedback from the highest remainder position.
        let feedback_ptr = remainder[PARITY_LEN - 1].as_ptr() as *const __m128i;
        let feedback_vec = unsafe { _mm_loadu_si128(feedback_ptr) };
        let feedback = _mm_xor_si128(data_vec, feedback_vec);

        // Shift remainder right.
        for i in (1..PARITY_LEN).rev() {
            remainder[i] = remainder[i - 1];
        }
        remainder[0] = [0u8; BATCH];

        // Apply generator polynomial multiplication using lookup tables.
        match PARITY_LEN {
            16 => apply_tables_for_parity!(PARITY_LEN, RS_255_239_TABLES, 17, &feedback, remainder),
            32 => apply_tables_for_parity!(PARITY_LEN, RS_255_223_TABLES, 33, &feedback, remainder),
            64 => apply_tables_for_parity!(PARITY_LEN, RS_255_191_TABLES, 65, &feedback, remainder),
            _ => unreachable!(),
        }
    }

    let (data_codewords, parity_codewords) =
        crate::transpose_from_simd::<BATCH, DATA_LEN, PARITY_LEN>(&transposed_data, &remainder);

    for i in 0..BATCH {
        writer.write_all(&data_codewords[i])?;
        writer.write_all(&parity_codewords[i])?;
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,ssse3")]
unsafe fn apply_ssse3_gf_multiplication<const BATCH: usize>(
    feedback: &core::arch::x86_64::__m128i,
    remainder_row: &mut [u8; BATCH],
    table: &crate::reed_solomon::simd::GfFourBitTables,
) {
    use core::arch::x86_64::*;

    // Extract low and high nibbles from feedback vector.
    let low_nibble_mask = _mm_set1_epi8(0x0F_u8 as i8);
    let low_nibbles = _mm_and_si128(*feedback, low_nibble_mask);

    // For high nibbles, first shift right by 4 bits per byte.
    let high_nibbles = _mm_srli_epi16::<4>(*feedback);
    let high_nibbles = _mm_and_si128(high_nibbles, low_nibble_mask);

    // Perform table lookups for low nibbles using SSSE3 shuffle.
    let low_table_ptr = table.low_four.as_ptr() as *const __m128i;
    let low_table = unsafe { _mm_loadu_si128(low_table_ptr) };
    let low_products = _mm_shuffle_epi8(low_table, low_nibbles);

    // Perform table lookups for high nibbles using SSSE3 shuffle.
    let high_table_ptr = table.high_four.as_ptr() as *const __m128i;
    let high_table = unsafe { _mm_loadu_si128(high_table_ptr) };
    let high_products = _mm_shuffle_epi8(high_table, high_nibbles);

    // Combine low and high products.
    let products = _mm_xor_si128(low_products, high_products);

    // XOR with current remainder.
    let current_ptr = remainder_row.as_ptr() as *const __m128i;
    let current = unsafe { _mm_loadu_si128(current_ptr) };
    let result = _mm_xor_si128(current, products);
    let result_ptr = remainder_row.as_mut_ptr() as *mut __m128i;
    unsafe { _mm_storeu_si128(result_ptr, result) };
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn encode_simd_batch_neon<
    R: Write,
    const BATCH: usize,
    const DATA_LEN: usize,
    const PARITY_LEN: usize,
>(
    mut writer: R,
    batch_codewords: &[[u8; DATA_LEN]; BATCH],
) -> Result<()> {
    use core::arch::aarch64::*;

    use crate::reed_solomon::simd::{RS_255_191_TABLES, RS_255_223_TABLES, RS_255_239_TABLES};

    // Define a macro to reduce repetition in applying tables.
    macro_rules! apply_tables_for_parity {
        ($parity:expr, $tables:expr, $table_len:expr, $feedback:expr, $remainder:expr) => {
            for i in 0..$parity {
                if i < $table_len {
                    let table = &$tables[0][i];
                    unsafe {
                        apply_neon_gf_multiplication::<BATCH>($feedback, &mut $remainder[i], table);
                    }
                }
            }
        };
    }

    let transposed_data = crate::transpose_for_simd::<BATCH, DATA_LEN>(batch_codewords);

    // LFSR-based encoding with SIMD and lookup tables.
    let mut remainder = [[0u8; BATCH]; PARITY_LEN];

    // Process each data byte position (from highest to lowest).
    for data_bytes in transposed_data.iter().rev() {
        let data_vec = unsafe { vld1q_u8(data_bytes.as_ptr()) };

        // XOR with feedback from the highest remainder position.
        let feedback_vec = unsafe { vld1q_u8(remainder[PARITY_LEN - 1].as_ptr()) };
        let feedback = veorq_u8(data_vec, feedback_vec);

        // Shift remainder right.
        for i in (1..PARITY_LEN).rev() {
            remainder[i] = remainder[i - 1];
        }
        remainder[0] = [0u8; BATCH];

        // Apply generator polynomial multiplication using lookup tables.
        match PARITY_LEN {
            16 => apply_tables_for_parity!(PARITY_LEN, RS_255_239_TABLES, 17, &feedback, remainder),
            32 => apply_tables_for_parity!(PARITY_LEN, RS_255_223_TABLES, 33, &feedback, remainder),
            64 => apply_tables_for_parity!(PARITY_LEN, RS_255_191_TABLES, 65, &feedback, remainder),
            _ => unreachable!(),
        }
    }

    let (data_codewords, parity_codewords) =
        crate::transpose_from_simd::<BATCH, DATA_LEN, PARITY_LEN>(&transposed_data, &remainder);

    for i in 0..BATCH {
        writer.write_all(&data_codewords[i])?;
        writer.write_all(&parity_codewords[i])?;
    }

    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn apply_neon_gf_multiplication<const BATCH: usize>(
    feedback: &core::arch::aarch64::uint8x16_t,
    remainder_row: &mut [u8; BATCH],
    table: &crate::reed_solomon::simd::GfFourBitTables,
) {
    use core::arch::aarch64::*;

    // Extract low and high nibbles from feedback vector.
    let low_nibble_mask = vdupq_n_u8(0x0F);
    let low_nibbles = vandq_u8(*feedback, low_nibble_mask);
    let high_nibbles = vshrq_n_u8::<4>(*feedback);

    // Perform table lookups for low nibbles.
    let low_table = unsafe { vld1q_u8(table.low_four.as_ptr()) };
    let low_products = vqtbl1q_u8(low_table, low_nibbles);

    // Perform table lookups for high nibbles.
    let high_table = unsafe { vld1q_u8(table.high_four.as_ptr()) };
    let high_products = vqtbl1q_u8(high_table, high_nibbles);

    // Combine low and high products.
    let products = veorq_u8(low_products, high_products);

    // XOR with current remainder.
    let current = unsafe { vld1q_u8(remainder_row.as_ptr()) };
    let result = veorq_u8(current, products);
    unsafe { vst1q_u8(remainder_row.as_mut_ptr(), result) };
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_ec_encoder_none_passthrough() {
        let mut output = Vec::new();
        let mut ec_encoder =
            ECCEncoder::new(&mut output, ErrorCorrection::None, SimdOverride::Auto);

        let test_data = b"Hello, World!";
        ec_encoder.write_all(test_data).unwrap();

        let _final_output = ec_encoder.finish().unwrap();

        assert_eq!(output, test_data);
    }

    #[test]
    fn test_ec_encoder_standard_encoding() {
        let mut output = Vec::new();
        let mut ec_encoder =
            ECCEncoder::new(&mut output, ErrorCorrection::Standard, SimdOverride::Auto);

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
        let mut ec_encoder =
            ECCEncoder::new(&mut output, ErrorCorrection::Standard, SimdOverride::Auto);

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

    #[test]
    fn test_all_simd_paths_on_current_arch() {
        fn test_simd_path_consistency(
            error_correction: ErrorCorrection,
            simd_override: SimdOverride,
            test_name: &str,
        ) -> bool {
            let test_data =
                b"Hello, World! This is a test of SIMD consistency across all paths.".repeat(20);

            let mut scalar_output = Vec::new();
            let mut scalar_encoder = ECCEncoder::new(
                &mut scalar_output,
                error_correction,
                SimdOverride::ForceScalar,
            );
            scalar_encoder.write_all(&test_data).unwrap();
            scalar_encoder.finish().unwrap();

            let mut simd_output = Vec::new();
            let mut simd_encoder =
                ECCEncoder::new(&mut simd_output, error_correction, simd_override);
            simd_encoder.write_all(&test_data).unwrap();
            simd_encoder.finish().unwrap();

            let matches = scalar_output == simd_output;
            if matches {
                println!("✓ {test_name} - outputs match");
            } else {
                println!("✗ {test_name} - outputs differ!");
                println!("  Scalar output length: {}", scalar_output.len());
                println!("  SIMD output length: {}", simd_output.len());
                println!("  Scalar hash: {}", blake3::hash(&scalar_output));
                println!("  SIMD hash: {}", blake3::hash(&simd_output));
            }
            matches
        }

        let error_corrections = [
            ErrorCorrection::Standard,
            ErrorCorrection::Paranoid,
            ErrorCorrection::Extreme,
        ];

        let mut all_passed = true;

        for &ec in &error_corrections {
            let ec_name = match ec {
                ErrorCorrection::None => "None",
                ErrorCorrection::Standard => "Standard",
                ErrorCorrection::Paranoid => "Paranoid",
                ErrorCorrection::Extreme => "Extreme",
            };

            #[cfg(target_arch = "x86_64")]
            {
                if is_x86_feature_detected!("sse2") && is_x86_feature_detected!("gfni") {
                    let test_name = format!("SSE2 + GFNI vs Scalar - {ec_name}");
                    all_passed &=
                        test_simd_path_consistency(ec, SimdOverride::ForceSse2Gfni, &test_name);
                } else {
                    println!("⊗ SSE2 + GFNI not available on this CPU - {ec_name}");
                }

                if is_x86_feature_detected!("ssse3") {
                    let test_name = format!("SSSE3 vs Scalar - {ec_name}");
                    all_passed &=
                        test_simd_path_consistency(ec, SimdOverride::ForceSsse3, &test_name);
                } else {
                    println!("⊗ SSSE3 not available on this CPU - {ec_name}");
                }

                if is_x86_feature_detected!("avx2") {
                    let test_name = format!("AVX2 (pure) vs Scalar - {ec_name}");
                    all_passed &=
                        test_simd_path_consistency(ec, SimdOverride::ForceAvx2, &test_name);
                } else {
                    println!("⊗ AVX2 not available on this CPU - {ec_name}");
                }

                if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("gfni") {
                    let test_name = format!("AVX2 + GFNI vs Scalar - {ec_name}");
                    all_passed &=
                        test_simd_path_consistency(ec, SimdOverride::ForceAvx2Gfni, &test_name);
                } else {
                    println!("⊗ AVX2 + GFNI not available on this CPU - {ec_name}");
                }
            }

            #[cfg(all(target_arch = "aarch64", feature = "std"))]
            {
                // Test NEON if available
                if std::arch::is_aarch64_feature_detected!("neon") {
                    let test_name = format!("NEON vs Scalar - {ec_name}");
                    all_passed &=
                        test_simd_path_consistency(ec, SimdOverride::ForceNeon, &test_name);
                } else {
                    println!("⊗ NEON not available on this CPU - {ec_name}");
                }
            }

            #[cfg(not(any(
                target_arch = "x86_64",
                all(target_arch = "aarch64", feature = "std")
            )))]
            {
                println!("⊗ No SIMD paths available on this architecture - {ec_name}");
            }
        }

        assert!(
            all_passed,
            "One or more SIMD paths produced different outputs than scalar reference"
        );
    }
}
