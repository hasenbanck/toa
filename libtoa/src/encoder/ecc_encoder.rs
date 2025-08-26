#[cfg(target_arch = "x86_64")]
use crate::reed_solomon::get_generator_poly;
use crate::{
    ErrorCorrection, Result, Write,
    circular_buffer::CircularBuffer,
    reed_solomon::{code_255_191, code_255_223, code_255_239},
};

type EncodeFunction<W> = fn(&mut ECCEncoder<W>, &[u8]) -> Result<usize>;

fn encode_none<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    encoder.inner.write_all(data)?;
    Ok(data.len())
}

fn encode_standard<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    encoder.encode_with_rs::<_, 239, 16>(data, code_255_239::encode)
}

fn encode_paranoid<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    encoder.encode_with_rs::<_, 223, 32>(data, code_255_223::encode)
}

fn encode_extreme<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    encoder.encode_with_rs::<_, 191, 64>(data, code_255_191::encode)
}

#[cfg(target_arch = "x86_64")]
fn encode_standard_avx512<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_avx512::<239, 16>(data) }
}

#[cfg(target_arch = "x86_64")]
fn encode_paranoid_avx512<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_avx512::<223, 32>(data) }
}

#[cfg(target_arch = "x86_64")]
fn encode_extreme_avx512<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_avx512::<191, 64>(data) }
}

#[cfg(target_arch = "x86_64")]
fn encode_standard_avx2<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_avx2::<239, 16>(data) }
}

#[cfg(target_arch = "x86_64")]
fn encode_paranoid_avx2<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_avx2::<223, 32>(data) }
}

#[cfg(target_arch = "x86_64")]
fn encode_extreme_avx2<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_avx2::<191, 64>(data) }
}

#[cfg(target_arch = "aarch64")]
fn encode_standard_neon<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_neon::<239, 16>(data) }
}

#[cfg(target_arch = "aarch64")]
fn encode_paranoid_neon<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_neon::<223, 32>(data) }
}

#[cfg(target_arch = "aarch64")]
fn encode_extreme_neon<W: Write>(encoder: &mut ECCEncoder<W>, data: &[u8]) -> Result<usize> {
    unsafe { encoder.encode_batch_neon::<191, 64>(data) }
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
        const ECC_BATCH_SIZE_AVX512: usize = 64;
        const ECC_BATCH_SIZE_AVX2: usize = 32;

        match error_correction {
            ErrorCorrection::None => (None, 1),
            ErrorCorrection::Standard => {
                if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_standard_avx512 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX512,
                    )
                } else if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_standard_avx2 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX2,
                    )
                } else {
                    (None, 1)
                }
            }
            ErrorCorrection::Paranoid => {
                if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_paranoid_avx512 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX512,
                    )
                } else if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_paranoid_avx2 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX2,
                    )
                } else {
                    (None, 1)
                }
            }
            ErrorCorrection::Extreme => {
                if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_extreme_avx512 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX512,
                    )
                } else if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("gfni") {
                    (
                        Some(encode_extreme_avx2 as EncodeFunction<W>),
                        ECC_BATCH_SIZE_AVX2,
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

        const ECC_BATCH_SIZE_NEON: usize = 16;

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

    /// Create a new ECCWriter with the specified error correction level.
    pub fn new(inner: W, error_correction: ErrorCorrection) -> Self {
        let (encode_fn_simd, simd_batch_size) = Self::get_simd_function(error_correction);

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
    fn encode_with_rs<F, const DATA_LEN: usize, const PARITY_LEN: usize>(
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

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,gfni")]
    unsafe fn encode_batch_avx512<const DATA_LEN: usize, const PARITY_LEN: usize>(
        &mut self,
        data: &[u8],
    ) -> Result<usize> {
        const BATCH: usize = 64;
        let batch_data_size = BATCH * DATA_LEN;
        let mut input_processed = 0;

        if self.buffer.available_data() >= batch_data_size {
            let mut batch_codewords = [[0u8; DATA_LEN]; BATCH];

            if self
                .buffer
                .fill_batch_from_buffer::<BATCH, DATA_LEN>(&mut batch_codewords, batch_data_size)
            {
                unsafe {
                    encode_simd_batch_avx512::<_, BATCH, DATA_LEN, PARITY_LEN>(
                        &mut self.inner,
                        &batch_codewords,
                    )?;
                }

                self.buffer.consume(batch_data_size);
                return Ok(0);
            }
        }

        // Try to process aligned data directly without copying.
        let (left, aligned, _right) = unsafe { data.align_to::<[u8; DATA_LEN]>() };

        if left.is_empty() && aligned.len() >= BATCH {
            // Data is perfectly aligned and we have enough for at least one batch!
            let batches_possible = aligned.len() / BATCH;

            for batch_idx in 0..batches_possible {
                let batch_start = batch_idx * BATCH;
                let batch_slice = &aligned[batch_start..batch_start + BATCH];

                // Safe transmute: we know the slice has exactly BATCH elements of [u8; DATA_LEN]
                let batch_codewords: &[[u8; DATA_LEN]; BATCH] =
                    unsafe { &*(batch_slice.as_ptr() as *const [[u8; DATA_LEN]; BATCH]) };

                unsafe {
                    encode_simd_batch_avx512::<_, BATCH, DATA_LEN, PARITY_LEN>(
                        &mut self.inner,
                        batch_codewords,
                    )?;
                }

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

            unsafe {
                encode_simd_batch_avx512::<_, BATCH, DATA_LEN, PARITY_LEN>(
                    &mut self.inner,
                    &batch_codewords,
                )?;
            }

            pos += batch_data_size;
            input_processed += batch_data_size;
        }

        Ok(input_processed)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2,gfni")]
    unsafe fn encode_batch_avx2<const DATA_LEN: usize, const PARITY_LEN: usize>(
        &mut self,
        data: &[u8],
    ) -> Result<usize> {
        const BATCH: usize = 32;
        let batch_data_size = BATCH * DATA_LEN;
        let mut input_processed = 0;

        if self.buffer.available_data() >= batch_data_size {
            let mut batch_codewords = [[0u8; DATA_LEN]; BATCH];

            if self
                .buffer
                .fill_batch_from_buffer::<BATCH, DATA_LEN>(&mut batch_codewords, batch_data_size)
            {
                unsafe {
                    encode_simd_batch_avx2::<_, BATCH, DATA_LEN, PARITY_LEN>(
                        &mut self.inner,
                        &batch_codewords,
                    )?;
                }

                self.buffer.consume(batch_data_size);
                return Ok(0);
            }
        }

        // Try to process aligned data directly without copying.
        let (left, aligned, _right) = unsafe { data.align_to::<[u8; DATA_LEN]>() };

        if left.is_empty() && aligned.len() >= BATCH {
            // Data is perfectly aligned and we have enough for at least one batch!
            let batches_possible = aligned.len() / BATCH;

            for batch_idx in 0..batches_possible {
                let batch_start = batch_idx * BATCH;
                let batch_slice = &aligned[batch_start..batch_start + BATCH];

                // Safe transmute: we know the slice has exactly BATCH elements of [u8; DATA_LEN]
                let batch_codewords: &[[u8; DATA_LEN]; BATCH] =
                    unsafe { &*(batch_slice.as_ptr() as *const [[u8; DATA_LEN]; BATCH]) };

                unsafe {
                    encode_simd_batch_avx2::<_, BATCH, DATA_LEN, PARITY_LEN>(
                        &mut self.inner,
                        batch_codewords,
                    )?;
                }

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

            unsafe {
                encode_simd_batch_avx2::<_, BATCH, DATA_LEN, PARITY_LEN>(
                    &mut self.inner,
                    &batch_codewords,
                )?;
            }

            pos += batch_data_size;
            input_processed += batch_data_size;
        }

        Ok(input_processed)
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn encode_batch_neon<const DATA_LEN: usize, const PARITY_LEN: usize>(
        &mut self,
        data: &[u8],
    ) -> Result<usize> {
        const BATCH: usize = 16;
        let batch_data_size = BATCH * DATA_LEN;
        let mut input_processed = 0;

        if self.buffer.available_data() >= batch_data_size {
            let mut batch_codewords = [[0u8; DATA_LEN]; BATCH];

            if self
                .buffer
                .fill_batch_from_buffer::<BATCH, DATA_LEN>(&mut batch_codewords, batch_data_size)
            {
                unsafe {
                    encode_simd_batch_neon::<_, BATCH, DATA_LEN, PARITY_LEN>(
                        &mut self.inner,
                        &batch_codewords,
                    )?;
                }

                self.buffer.consume(batch_data_size);
                return Ok(0);
            }
        }

        // Try to process aligned data directly without copying.
        let (left, aligned, _right) = unsafe { data.align_to::<[u8; DATA_LEN]>() };

        if left.is_empty() && aligned.len() >= BATCH {
            // Data is perfectly aligned and we have enough for at least one batch!
            let batches_possible = aligned.len() / BATCH;

            for batch_idx in 0..batches_possible {
                let batch_start = batch_idx * BATCH;
                let batch_slice = &aligned[batch_start..batch_start + BATCH];

                // Safe transmute: we know the slice has exactly BATCH elements of [u8; DATA_LEN]
                let batch_codewords: &[[u8; DATA_LEN]; BATCH] =
                    unsafe { &*(batch_slice.as_ptr() as *const [[u8; DATA_LEN]; BATCH]) };

                unsafe {
                    encode_simd_batch_neon::<_, BATCH, DATA_LEN, PARITY_LEN>(
                        &mut self.inner,
                        batch_codewords,
                    )?;
                }

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

            unsafe {
                encode_simd_batch_neon::<_, BATCH, DATA_LEN, PARITY_LEN>(
                    &mut self.inner,
                    &batch_codewords,
                )?;
            }

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
#[target_feature(enable = "avx512f,gfni")]
unsafe fn encode_simd_batch_avx512<
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
        let data_vec = unsafe { _mm512_loadu_si512(data_bytes.as_ptr() as *const __m512i) };

        // XOR with feedback from the highest remainder position.
        let feedback_vec =
            unsafe { _mm512_loadu_si512(remainder[PARITY_LEN - 1].as_ptr() as *const __m512i) };
        let feedback = _mm512_xor_si512(data_vec, feedback_vec);

        // Shift remainder right.
        for i in (1..PARITY_LEN).rev() {
            remainder[i] = remainder[i - 1];
        }
        remainder[0] = [0u8; BATCH];

        // Apply generator polynomial multiplication with GFNI.
        for (i, &g_coeff) in gen_poly[..PARITY_LEN].iter().enumerate() {
            if g_coeff != 0 {
                let g_vec = _mm512_set1_epi8(g_coeff as i8);
                let product = _mm512_gf2p8mul_epi8(feedback, g_vec);

                let current =
                    unsafe { _mm512_loadu_si512(remainder[i].as_ptr() as *const __m512i) };
                let result = _mm512_xor_si512(current, product);
                unsafe { _mm512_storeu_si512(remainder[i].as_mut_ptr() as *mut __m512i, result) };
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
#[target_feature(enable = "avx2,gfni")]
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

    let transposed_data = crate::transpose_for_simd::<BATCH, DATA_LEN>(batch_codewords);
    let gen_poly = get_generator_poly::<PARITY_LEN>();

    // LFSR-based encoding with SIMD.
    let mut remainder = [[0u8; BATCH]; PARITY_LEN];

    // Process each data byte position (from highest to lowest).
    for data_bytes in transposed_data.iter().rev() {
        let data_vec = unsafe { _mm256_loadu_si256(data_bytes.as_ptr() as *const __m256i) };

        // XOR with feedback from the highest remainder position.
        let feedback_vec =
            unsafe { _mm256_loadu_si256(remainder[PARITY_LEN - 1].as_ptr() as *const __m256i) };
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

                let current =
                    unsafe { _mm256_loadu_si256(remainder[i].as_ptr() as *const __m256i) };
                let result = _mm256_xor_si256(current, product);
                unsafe { _mm256_storeu_si256(remainder[i].as_mut_ptr() as *mut __m256i, result) };
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
    #[cfg(any(target_arch = "x86_64", all(target_arch = "aarch64", feature = "std")))]
    use crate::{
        reed_solomon::{code_255_191, code_255_223, code_255_239},
        tests::Lcg,
    };

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
    fn test_ec_encoder_standard_encoding() {
        let mut output = Vec::new();
        let mut ec_encoder = ECCEncoder::new(&mut output, ErrorCorrection::Standard);

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
        let mut ec_encoder = ECCEncoder::new(&mut output, ErrorCorrection::Standard);

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
    #[cfg(target_arch = "x86_64")]
    fn test_direct_simd_vs_scalar_functions() {
        if !is_x86_feature_detected!("avx2") || !is_x86_feature_detected!("gfni") {
            println!("GFNI not supported");
            return;
        }
        println!("GFNI supported");

        fn test_simd_batch<const BATCH: usize, const DATA_LEN: usize, const PARITY_LEN: usize>(
            rng: &mut Lcg,
            encode_fn: fn(&[u8; DATA_LEN]) -> [u8; PARITY_LEN],
            simd_fn: impl FnOnce(&mut Vec<u8>, &[[u8; DATA_LEN]; BATCH]) -> Result<()>,
            test_name: &str,
        ) {
            let mut batch_data = [[0u8; DATA_LEN]; BATCH];
            for codeword in &mut batch_data {
                rng.fill_buffer(codeword);
            }

            let mut scalar_output = Vec::new();
            let mut simd_output = Vec::new();

            for codeword in &batch_data {
                let parity = encode_fn(codeword);
                scalar_output.extend_from_slice(codeword);
                scalar_output.extend_from_slice(&parity);
            }

            simd_fn(&mut simd_output, &batch_data).unwrap();

            assert_eq!(
                blake3::hash(&scalar_output),
                blake3::hash(&simd_output),
                "{test_name}"
            );
        }

        let mut rng = Lcg::new(0x123456789ABCDEF0);

        test_simd_batch::<32, 239, 16>(
            &mut rng,
            code_255_239::encode,
            |out, data| unsafe { encode_simd_batch_avx2::<_, 32, 239, 16>(out, data) },
            "Direct AVX2 vs scalar mismatch for Standard error correction",
        );

        test_simd_batch::<32, 223, 32>(
            &mut rng,
            code_255_223::encode,
            |out, data| unsafe { encode_simd_batch_avx2::<_, 32, 223, 32>(out, data) },
            "Direct AVX2 vs scalar mismatch for Paranoid error correction",
        );

        test_simd_batch::<32, 191, 64>(
            &mut rng,
            code_255_191::encode,
            |out, data| unsafe { encode_simd_batch_avx2::<_, 32, 191, 64>(out, data) },
            "Direct AVX2 vs scalar mismatch for Extreme error correction",
        );

        if is_x86_feature_detected!("avx512f") {
            test_simd_batch::<64, 239, 16>(
                &mut rng,
                code_255_239::encode,
                |out, data| unsafe { encode_simd_batch_avx512::<_, 64, 239, 16>(out, data) },
                "Direct AVX512 vs scalar mismatch for Standard error correction",
            );

            test_simd_batch::<64, 223, 32>(
                &mut rng,
                code_255_223::encode,
                |out, data| unsafe { encode_simd_batch_avx512::<_, 64, 223, 32>(out, data) },
                "Direct AVX512 vs scalar mismatch for Paranoid error correction",
            );

            test_simd_batch::<64, 191, 64>(
                &mut rng,
                code_255_191::encode,
                |out, data| unsafe { encode_simd_batch_avx512::<_, 64, 191, 64>(out, data) },
                "Direct AVX512 vs scalar mismatch for Extreme error correction",
            );
        }
    }

    #[test]
    #[cfg(all(target_arch = "aarch64", feature = "std"))]
    fn test_direct_simd_vs_scalar_functions_neon() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            println!("NEON not supported");
            return;
        }
        println!("NEON supported");

        fn test_simd_batch<const BATCH: usize, const DATA_LEN: usize, const PARITY_LEN: usize>(
            rng: &mut Lcg,
            encode_fn: fn(&[u8; DATA_LEN]) -> [u8; PARITY_LEN],
            simd_fn: impl FnOnce(&mut Vec<u8>, &[[u8; DATA_LEN]; BATCH]) -> Result<()>,
            test_name: &str,
        ) {
            let mut batch_data = [[0u8; DATA_LEN]; BATCH];
            for codeword in &mut batch_data {
                rng.fill_buffer(codeword);
            }

            let mut scalar_output = Vec::new();
            let mut simd_output = Vec::new();

            for codeword in &batch_data {
                let parity = encode_fn(codeword);
                scalar_output.extend_from_slice(codeword);
                scalar_output.extend_from_slice(&parity);
            }

            simd_fn(&mut simd_output, &batch_data).unwrap();

            assert_eq!(
                blake3::hash(&scalar_output),
                blake3::hash(&simd_output),
                "{test_name}"
            );
        }

        let mut rng = Lcg::new(0x123456789ABCDEF0);

        test_simd_batch::<16, 239, 16>(
            &mut rng,
            code_255_239::encode,
            |out, data| unsafe { encode_simd_batch_neon::<_, 16, 239, 16>(out, data) },
            "Direct NEON vs scalar mismatch for Standard error correction",
        );

        test_simd_batch::<16, 223, 32>(
            &mut rng,
            code_255_223::encode,
            |out, data| unsafe { encode_simd_batch_neon::<_, 16, 223, 32>(out, data) },
            "Direct NEON vs scalar mismatch for Paranoid error correction",
        );

        test_simd_batch::<16, 191, 64>(
            &mut rng,
            code_255_191::encode,
            |out, data| unsafe { encode_simd_batch_neon::<_, 16, 191, 64>(out, data) },
            "Direct NEON vs scalar mismatch for Extreme error correction",
        );
    }
}
