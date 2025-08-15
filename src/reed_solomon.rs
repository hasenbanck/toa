//! Stack only Reed–Solomon implementation.
//!
//! ## Specification
//!
//! - Field: GF(2^8) = GF(256)
//! - Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
//! - Generator: α = 2
//! - Code: (n=64, k=32, t=16)
//!
//! ## License
//!
//! The code in this file is in the public domain or can be licensed under the Apache 2 License.

/// The size of the data payload.
pub const DATA_LEN: usize = 32;

/// The size of the parity bytes.
pub const PARITY_LEN: usize = 32;

/// Overall codeword size.
pub const CODEWORD_SIZE: usize = DATA_LEN + PARITY_LEN;

/// Safe upper bound for intermediate polynomials.
const MAX_POLY: usize = CODEWORD_SIZE;

// GF(256) parameters
const PRIMITIVE_POLY: u16 = 0x11D; // (x^8 + x^4 + x^3 + x^2 + 1)
const GF_EXP_LEN: usize = 512;
const GF_LOG_LEN: usize = 256;

struct GfTables {
    exp: [u8; GF_EXP_LEN],
    log: [u8; GF_LOG_LEN],
}

const fn build_gf_tables() -> GfTables {
    let mut exp = [0u8; GF_EXP_LEN];
    let mut log = [0u8; GF_LOG_LEN];

    // α = 2, build α^0..α^254
    let mut i = 0usize;
    let mut x: u16 = 1;
    while i < 255 {
        exp[i] = (x & 0xFF) as u8;
        log[(x & 0xFF) as usize] = i as u8;
        x <<= 1;
        if (x & 0x100) != 0 {
            x ^= PRIMITIVE_POLY;
        }
        i += 1;
    }

    // Duplicate exp for simple indexing without modulo.
    let mut j = 255usize;
    while j < GF_EXP_LEN {
        exp[j] = exp[j - 255];
        j += 1;
    }

    // Ensure log[0] = 0 (we won't use it for multiplicative ops).
    log[0] = 0;

    GfTables { exp, log }
}

const GF_TABLES: GfTables = build_gf_tables();

#[inline(always)]
const fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        let idx = GF_TABLES.log[a as usize] as usize + GF_TABLES.log[b as usize] as usize;
        GF_TABLES.exp[idx]
    }
}

#[inline(always)]
const fn gf_div(a: u8, b: u8) -> u8 {
    debug_assert!(b != 0);
    if a == 0 {
        0
    } else {
        let la = GF_TABLES.log[a as usize] as usize;
        let lb = GF_TABLES.log[b as usize] as usize;
        let idx = la + 255 - lb;
        GF_TABLES.exp[idx]
    }
}

#[inline(always)]
const fn gf_alpha_pow(power: isize) -> u8 {
    let mut p = power % 255;
    if p < 0 {
        p += 255;
    }
    GF_TABLES.exp[p as usize]
}

#[inline(always)]
const fn gf_pow_primitive_const(power: usize) -> u8 {
    // const-friendly primitive power (α^power)
    // power % 255 and then index exp
    let idx = power % 255;
    GF_TABLES.exp[idx]
}

/// Multiply polynomial `g` by (x - root) where root = α^i.
const fn mul_by_x_minus_root_const(
    g: [u8; PARITY_LEN + 1],
    g_len: usize,
    root: u8,
) -> ([u8; PARITY_LEN + 1], usize) {
    let mut res = [0u8; PARITY_LEN + 1];

    // res = g * (x + root) = g*x + g*root
    let mut i = 0;
    while i < g_len {
        // Contribution from g*x (g[i] becomes coefficient of x^(i+1)).
        res[i + 1] ^= g[i];
        // Contribution from g*root (g[i]*root is coefficient of x^i).
        res[i] ^= gf_mul(g[i], root);
        i += 1;
    }

    let mut new_len = g_len + 1;
    if new_len > PARITY_LEN + 1 {
        new_len = PARITY_LEN + 1;
    }
    while new_len > 1 && res[new_len - 1] == 0 {
        new_len -= 1;
    }
    (res, new_len)
}

const fn gen_poly_const() -> [u8; PARITY_LEN + 1] {
    let mut g = [0u8; PARITY_LEN + 1];
    g[0] = 1;
    let mut g_len = 1usize;
    let mut i = 1usize;
    while i <= PARITY_LEN {
        let root = gf_pow_primitive_const(i);
        let (next, next_len) = mul_by_x_minus_root_const(g, g_len, root);
        g = next;
        g_len = next_len;
        i += 1;
    }

    g
}

const GEN_POLY: [u8; PARITY_LEN + 1] = gen_poly_const();

#[inline(always)]
fn poly_eval(poly: &[u8], len: usize, x: u8) -> u8 {
    if len == 0 {
        return 0;
    }
    let mut acc = poly[len - 1];
    for i in (0..len - 1).rev() {
        acc = gf_mul(acc, x) ^ poly[i];
    }
    acc
}

/// Multiply a (len_a) and b (len_b) into `out`, set out_len.
/// out capacity must be >= len_a + len_b - 1 (we use MAX_POLY).
fn poly_mul_into(
    a: &[u8],
    len_a: usize,
    b: &[u8],
    len_b: usize,
    out: &mut [u8],
    out_len: &mut usize,
) {
    if len_a == 0 || len_b == 0 {
        out[0] = 0;
        *out_len = 1;
        return;
    }
    let res_len = len_a + len_b - 1;

    out[..res_len].fill(0);

    for i in 0..len_a {
        let ai = a[i];
        if ai == 0 {
            continue;
        }
        for j in 0..len_b {
            let bj = b[j];
            if bj == 0 {
                continue;
            }
            out[i + j] ^= gf_mul(ai, bj);
        }
    }
    // trim
    let mut l = res_len;
    while l > 1 && out[l - 1] == 0 {
        l -= 1;
    }
    *out_len = l;
}

fn derivative_char2(poly: &[u8], len: usize, out: &mut [u8], out_len: &mut usize) {
    if len <= 1 {
        out[0] = 0;
        *out_len = 1;
        return;
    }
    let mut l = len - 1;
    for i in 0..l {
        let idx = i + 1;
        if (idx & 1) == 1 {
            out[i] = poly[idx];
        } else {
            out[i] = 0;
        }
    }
    while l > 1 && out[l - 1] == 0 {
        l -= 1;
    }
    *out_len = l;
}

/// Finds the error locator polynomial `Λ(x)` for a given syndrome sequence `S(x)`.
///
/// This is an optimized implementation of the Berlekamp-Massey algorithm.
///
/// # Arguments
/// * `synd`: The syndrome polynomial coefficients `[s_0, s_1, ..., s_{2t-1}]`.
/// * `lambda_out`: An output buffer to store the resulting locator polynomial `Λ(x)`.
/// * `lambda_len`: An output parameter to store the length of `Λ(x)`.
fn berlekamp_massey(synd: &[u8], lambda_out: &mut [u8], lambda_len: &mut usize) {
    // Λ(x), the error locator polynomial. Initialized to 1.
    let mut lambda = [0u8; PARITY_LEN + 1];
    lambda[0] = 1;
    let mut current_lambda_len = 1;

    // B(x), the previous Λ(x) from the last time `l` was updated. Initialized to 1.
    let mut b_poly = [0u8; PARITY_LEN + 1];
    b_poly[0] = 1;
    let mut b_len = 1;

    // `l` is the degree of the current locator polynomial (number of known errors).
    let mut l = 0;
    // `m` is the number of steps since `l` was last updated.
    let mut m = 1;
    // `d_prime` is the discrepancy from the last time `l` was updated.
    let mut d_prime = 1;

    // Iterate through all syndromes. `n` is the current time step.
    for n in 0..synd.len() {
        // 1. Calculate the discrepancy `d`.
        // This is the error in the next term of the sequence predicted by the current LFSR (lambda).
        // d = s_n + λ_1*s_{n-1} + ... + λ_l*s_{n-l}
        let mut d = synd[n];
        for i in 1..=l {
            if lambda[i] != 0 {
                d ^= gf_mul(lambda[i], synd[n - i]);
            }
        }

        if d == 0 {
            // 2a. Discrepancy is zero. Our current `lambda` is still correct.
            // We just increase the shift `m`.
            m += 1;
        } else {
            // 2b. Discrepancy is non-zero. We must update `lambda`.
            let t_poly = lambda; // Save a copy of the current lambda(x).
            let t_len = current_lambda_len;

            let scale_factor = gf_div(d, d_prime);

            // Update lambda: Λ(x) = Λ(x) - (d/d') * x^m * B(x)
            let required_len = b_len + m;
            if current_lambda_len < required_len {
                current_lambda_len = required_len;
            }
            for i in 0..b_len {
                if b_poly[i] != 0 {
                    lambda[i + m] ^= gf_mul(scale_factor, b_poly[i]);
                }
            }

            // Check if we need to update the LFSR length `l`.
            if 2 * l <= n {
                l = n + 1 - l;
                d_prime = d;
                b_poly = t_poly; // The old lambda becomes the new B(x).
                b_len = t_len; // Use the length of the old lambda.
                m = 1;
            } else {
                // The length `l` doesn't change.
                m += 1;
            }
        }
    }

    // The final length of the locator polynomial is `l + 1`.
    *lambda_len = l + 1;
    lambda_out[..*lambda_len].copy_from_slice(&lambda[..*lambda_len]);

    // Trim any trailing zeros that might have been introduced, although `l+1` should be correct.
    while *lambda_len > 1 && lambda_out[*lambda_len - 1] == 0 {
        *lambda_len -= 1;
    }
}

/// Encode 32 bytes parity for 32 bytes data.
///
/// This implementation uses a LFSR-based method.
pub fn encode(data: &[u8; DATA_LEN]) -> [u8; PARITY_LEN] {
    let g = GEN_POLY;

    // The generator polynomial g(x) has degree PARITY_LEN. g_len is PARITY_LEN + 1.
    // We only need the coefficients g_0, g_1, ..., g_{PARITY_LEN-1}.
    // The leading coefficient g_{PARITY_LEN} is 1 and is implicit.
    let mut remainder = [0u8; PARITY_LEN];

    // Process data from the highest degree to lowest.
    for &byte in data.iter().rev() {
        let feedback = byte ^ remainder[PARITY_LEN - 1];
        remainder.rotate_right(1);
        remainder[0] = 0;

        // If feedback is non-zero, subtract feedback_term * g(x)
        if feedback != 0 {
            for (r, &gcoef) in remainder.iter_mut().zip(&g[..PARITY_LEN]) {
                *r ^= gf_mul(gcoef, feedback);
            }
        }
    }

    remainder
}

fn calculate_syndromes(c: &mut [u8; CODEWORD_SIZE], syndrome: &mut [u8; PARITY_LEN]) -> bool {
    let mut all_zero = true;

    let mut x = 1u8;
    let alpha = gf_alpha_pow(1); // which is 2
    for i in 0..PARITY_LEN {
        x = gf_mul(x, alpha); // x = α^(i+1)
        let s = poly_eval(c, CODEWORD_SIZE, x);
        syndrome[i] = s;
        if s != 0 {
            all_zero = false;
        }
    }

    all_zero
}

/// Calculates the error evaluator polynomial, Omega(x).
/// Omega(x) = (Syndromes(x) * Lambda(x)) mod x^{PARITY_LEN}
fn calculate_error_evaluator_poly(
    syndromes: &[u8; PARITY_LEN],
    lambda: &[u8; PARITY_LEN + 1],
    lambda_len: usize,
) -> ([u8; PARITY_LEN], usize) {
    let mut prod = [0u8; MAX_POLY];
    let mut prod_len = 0;

    // Multiply S(x) and Λ(x)
    poly_mul_into(
        syndromes,
        PARITY_LEN,
        lambda,
        lambda_len,
        &mut prod,
        &mut prod_len,
    );

    // The result is truncated to the degree of PARITY_LEN - 1.
    // Equivalent to `mod x^{PARITY_LEN}`.
    let omega_len = prod_len.min(PARITY_LEN);
    let mut omega = [0u8; PARITY_LEN];
    omega[..omega_len].copy_from_slice(&prod[..omega_len]);

    (omega, omega_len)
}

/// Calculates the error magnitudes using Forney's algorithm.
/// Magnitude_j = - Omega(X_j⁻¹) / Lambda'(X_j⁻¹)
fn calculate_error_magnitudes(
    err_pos: &[usize; PARITY_LEN / 2],
    err_count: usize,
    omega: &[u8; PARITY_LEN],
    omega_len: usize,
    lambda: &[u8; PARITY_LEN + 1],
    lambda_len: usize,
) -> Result<[u8; PARITY_LEN / 2], &'static str> {
    // We need the formal derivative of Lambda, Λ'(x).
    let mut lambda_deriv = [0u8; PARITY_LEN + 1];
    let mut lambda_deriv_len = 0;
    derivative_char2(lambda, lambda_len, &mut lambda_deriv, &mut lambda_deriv_len);

    let mut magnitudes = [0u8; PARITY_LEN / 2];

    for i in 0..err_count {
        let pos = err_pos[i];
        let x_inv = gf_alpha_pow(-(pos as isize));

        // Evaluate Omega at the inverse error location.
        let omega_val = poly_eval(omega, omega_len, x_inv);

        // Evaluate the derivative of Lambda at the inverse error location.
        let denom = poly_eval(&lambda_deriv, lambda_deriv_len, x_inv);
        if denom == 0 {
            // This indicates a decoder failure, possibly due to too many errors.
            return Err("Zero derivative at error position (cannot invert)");
        }

        // In GF(2^n), negation is the identity op, so -A = A.
        magnitudes[i] = gf_div(omega_val, denom);
    }

    Ok(magnitudes)
}

fn find_error_locations(
    lambda: &[u8; PARITY_LEN + 1],
    lambda_len: usize,
    num_errors: usize,
) -> Result<([usize; PARITY_LEN / 2], usize), &'static str> {
    let mut err_pos = [0usize; PARITY_LEN / 2];
    let mut err_count = 0usize;

    for pos in 0..CODEWORD_SIZE {
        let x_inv = gf_alpha_pow(-(pos as isize));
        let val = poly_eval(lambda, lambda_len, x_inv);
        if val == 0 {
            if err_count < PARITY_LEN {
                err_pos[err_count] = pos;
                err_count += 1;
            } else {
                return Err("Too many roots found");
            }
        }
    }

    if err_count == 0 {
        return Err("No error positions found");
    }

    if err_count != num_errors {
        return Err("Mismatch between locator degree and roots found");
    }

    if err_count > PARITY_LEN / 2 {
        return Err("Too many errors to correct");
    }

    Ok((err_pos, err_count))
}

fn find_error_locator_poly(
    syndromes: &mut [u8; PARITY_LEN],
) -> Result<([u8; PARITY_LEN + 1], usize, usize), &'static str> {
    let mut lambda = [0u8; PARITY_LEN + 1];
    let mut lambda_len = 0;
    berlekamp_massey(syndromes, &mut lambda, &mut lambda_len);

    if lambda_len == 0 {
        return Err("No error locator found");
    }

    let num_errors = lambda_len - 1;

    if num_errors == 0 {
        return Err("No errors located");
    }

    if num_errors > PARITY_LEN {
        return Err("Too many errors (locator degree > parity)");
    }

    Ok((lambda, lambda_len, num_errors))
}

/// Verifies that the corrected codeword is valid by checking if all syndromes are zero.
fn verify_correction(codeword_poly: &[u8; CODEWORD_SIZE]) -> bool {
    for i in 0..PARITY_LEN {
        let x = gf_alpha_pow((i + 1) as isize);
        if poly_eval(codeword_poly, CODEWORD_SIZE, x) != 0 {
            // A non-zero syndrome means correction failed.
            return false;
        }
    }
    // All syndromes are zero.
    true
}

/// Decode codeword in-place (data || parity).
///
/// Returns false if the data was not corrupted. False if the data was corrected but could be
/// corrected. Returns an error if the data was corrupted and could not be corrected.
///
/// The decoder is a classic Peterson–Gorenstein–Zierler decoder.
pub fn decode(codeword: &mut [u8; CODEWORD_SIZE]) -> Result<bool, &'static str> {
    // The received codeword polynomial is C(x) = D(x) * x^32 + P(x).
    // Our arrays store coefficients from the lowest degree to highest, so we arrange it as:
    // c = [p_0, p_1, ..., p_31, d_0, d_1, ..., d_31]
    let mut c = [0u8; CODEWORD_SIZE];
    c[..PARITY_LEN].copy_from_slice(&codeword[DATA_LEN..]); // P(x) coeffs
    c[PARITY_LEN..].copy_from_slice(&codeword[..DATA_LEN]); // D(x) coeffs

    // Step 1: Calculate Syndromes.
    let mut syndromes = [0u8; PARITY_LEN];
    if calculate_syndromes(&mut c, &mut syndromes) {
        // No errors found, the data is already correct.
        return Ok(false);
    }

    // Step 2: Find error locator polynomial Λ(x).
    let (lambda, lambda_len, num_errors) = find_error_locator_poly(&mut syndromes)?;

    // Step 3: Find error locations by finding the roots of Λ(x) (Chien Search).
    let (err_pos, err_count) = find_error_locations(&lambda, lambda_len, num_errors)?;

    // Step 4: Find error evaluator polynomial Ω(x).
    let (omega, omega_len) = calculate_error_evaluator_poly(&syndromes, &lambda, lambda_len);

    // Step 5: Find the error magnitudes using Forney's algorithm.
    let err_magnitudes =
        calculate_error_magnitudes(&err_pos, err_count, &omega, omega_len, &lambda, lambda_len)?;

    // Step 6: Correct the errors in the codeword polynomial.
    for i in 0..err_count {
        c[err_pos[i]] ^= err_magnitudes[i];
    }

    // Step 7: Verify that the correction was successful.
    if !verify_correction(&c) {
        return Err("Correction failed; syndromes are still non-zero");
    }

    // Step 8: Write corrected data back into the original buffer.
    codeword[..DATA_LEN].copy_from_slice(&c[PARITY_LEN..]);

    Ok(true)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    struct Lcg(u32);

    impl Lcg {
        fn new(seed: u32) -> Self {
            Lcg(seed)
        }
        fn next_u8(&mut self) -> u8 {
            self.0 = self.0.wrapping_mul(1664525).wrapping_add(1013904223);
            (self.0 >> 16) as u8
        }
        fn next_usize(&mut self, max: usize) -> usize {
            (self.next_u8() as usize) % max
        }
    }

    #[test]
    fn test_encode_decode_no_errors() {
        let mut data = [0u8; DATA_LEN];

        for i in 0..DATA_LEN {
            data[i] = i as u8;
        }

        let parity = encode(&data);

        let mut cw = [0u8; CODEWORD_SIZE];
        cw[..DATA_LEN].copy_from_slice(&data);
        cw[DATA_LEN..].copy_from_slice(&parity);

        decode(&mut cw).expect("should decode with no errors");

        assert_eq!(cw[..DATA_LEN], data);
    }

    #[test]
    fn test_random_correctable_errors() {
        let mut rng = Lcg::new(0x12345678);
        for _ in 0..20 {
            let mut data = [0u8; DATA_LEN];

            for i in 0..DATA_LEN {
                data[i] = rng.next_u8();
            }

            let parity = encode(&data);

            let mut cw = [0u8; CODEWORD_SIZE];
            cw[..DATA_LEN].copy_from_slice(&data);
            cw[DATA_LEN..].copy_from_slice(&parity);

            // Introduce up to 16 unique errors.
            let errors = 1 + (rng.next_usize(16));
            let mut positions = [usize::MAX; PARITY_LEN];
            let mut count = 0usize;
            while count < errors {
                let p = rng.next_usize(CODEWORD_SIZE);
                let mut unique = true;
                for j in 0..count {
                    if positions[j] == p {
                        unique = false;
                        break;
                    }
                }
                if unique {
                    positions[count] = p;
                    count += 1;
                }
            }

            for i in 0..count {
                let p = positions[i];
                let mut v = rng.next_u8();
                if v == 0 {
                    v = 1;
                }
                cw[p] ^= v;
            }

            decode(&mut cw).expect("should decode correctable errors");

            assert_eq!(cw[..DATA_LEN], data);
        }
    }

    #[test]
    fn test_too_many_errors_fails() {
        let mut rng = Lcg::new(0xDEADBEEF);

        let mut data = [0u8; DATA_LEN];

        for i in 0..DATA_LEN {
            data[i] = rng.next_u8();
        }

        let parity = encode(&data);

        let mut cw = [0u8; CODEWORD_SIZE];
        cw[..DATA_LEN].copy_from_slice(&data);
        cw[DATA_LEN..].copy_from_slice(&parity);

        // Introduce >16 errors.
        let mut positions = [usize::MAX; PARITY_LEN];
        let mut count = 0usize;
        while count < (PARITY_LEN / 2 + 1) {
            let p = rng.next_usize(CODEWORD_SIZE);
            let mut unique = true;
            for j in 0..count {
                if positions[j] == p {
                    unique = false;
                    break;
                }
            }
            if unique {
                positions[count] = p;
                count += 1;
            }
        }

        for i in 0..count {
            let p = positions[i];
            let mut v = rng.next_u8();
            if v == 0 {
                v = 1;
            }
            cw[p] ^= v;
        }

        let res = decode(&mut cw);

        assert!(res.is_err(), "decoding should fail with too many errors");
    }

    fn test_vector(data: [u8; 32], expected_parity: [u8; 32]) {
        let parity = encode(&data);

        assert_eq!(parity, expected_parity);

        let mut cw = [0u8; CODEWORD_SIZE];
        cw[..DATA_LEN].copy_from_slice(&data);
        cw[DATA_LEN..].copy_from_slice(&parity);

        decode(&mut cw).expect("should decode with no errors");

        assert_eq!(cw[..DATA_LEN], data);
    }

    #[test]
    fn test_specification_test_vector_1() {
        let data = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let expected_parity =
            hex!("0000000000000000000000000000000000000000000000000000000000000000");
        test_vector(data, expected_parity);
        test_vector(data, expected_parity);
    }

    #[test]
    fn test_specification_test_vector_2() {
        let data = hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let expected_parity =
            hex!("caabc74d87d23ad8a0a2bff5134bf7499e1b2859fb692e40b8d8e6fa8bfb5620");
        test_vector(data, expected_parity);
    }

    #[test]
    fn test_specification_test_vector_3() {
        let data = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let expected_parity =
            hex!("d8e4dab6534b241cb9afcb999503ec2d8c393a30f96e719970cee1d547f75acb");
        test_vector(data, expected_parity);
        test_vector(data, expected_parity);
    }

    #[test]
    fn test_specification_test_vector_4() {
        let data = hex!("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
        let expected_parity =
            hex!("0e54d343ed7e6ffaf7e650525685934403006ad1428d2c9d0869b67b1920bea6");
        test_vector(data, expected_parity);
        test_vector(data, expected_parity);
    }

    #[test]
    fn test_specification_test_vector_5() {
        let data = hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        let expected_parity =
            hex!("cedfc1cc789afb176bf1fb71a6756a5b315bdbc2322f987ff3aa7b0c7c2a6a7d");
        test_vector(data, expected_parity);
    }
}
