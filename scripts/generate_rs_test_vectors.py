#!/usr/bin/env python3
import galois
import numpy as np

GF = galois.GF(2**8, irreducible_poly=0x11b)
alpha = GF.primitive_element
assert alpha == 3
print(f"Primitive element α = {alpha}")

def build_generator_polynomial(num_roots):
    """Build generator polynomial with specified number of roots."""
    g = galois.Poly([1], field=GF)
    x = galois.Poly([1, 0], field=GF)
    for i in range(1, num_roots + 1):
        g = g * (x - alpha**i)
    return g

def rs_encode(data_bytes, parity_len):
    """Encode data with Reed-Solomon protection."""
    g = build_generator_polynomial(parity_len)
    data_list = list(data_bytes)
    data_gf = GF(data_list)
    data_poly = galois.Poly(data_gf[::-1], field=GF)
    shifted = data_poly * galois.Poly([1] + [0]*parity_len, field=GF)
    _, remainder = divmod(shifted, g)
    parity_coeffs = remainder.coeffs[::-1] if remainder.degree >= 0 else []
    parity = np.zeros(parity_len, dtype=np.uint8)
    parity[:len(parity_coeffs)] = [int(x) for x in parity_coeffs]
    return bytes(parity)

# Test vectors for RS(255,239)
print("\n=== RS(255,239) Test Vectors ===")

# Test 1: All zeros
data_239_zeros = bytes([0x00] * 239)
parity_239_zeros = rs_encode(data_239_zeros, 16)
print(f"Test 1 - All zeros:")
print(f"Parity: {parity_239_zeros.hex()}")

# Test 2: All ones
data_239_ones = bytes([0xff] * 239)
parity_239_ones = rs_encode(data_239_ones, 16)
print(f"Test 2 - All ones:")
print(f"Parity: {parity_239_ones.hex()}")

# Test 3: Incrementing pattern
data_239_inc = bytes(range(239))
parity_239_inc = rs_encode(data_239_inc, 16)
print(f"Test 3 - Incrementing:")
print(f"Parity: {parity_239_inc.hex()}")

# Test vectors for RS(255,223)
print("\n=== RS(255,223) Test Vectors ===")

# Test 1: All zeros
data_223_zeros = bytes([0x00] * 223)
parity_223_zeros = rs_encode(data_223_zeros, 32)
print(f"Test 1 - All zeros:")
print(f"Parity: {parity_223_zeros.hex()}")

# Test 2: All ones
data_223_ones = bytes([0xff] * 223)
parity_223_ones = rs_encode(data_223_ones, 32)
print(f"Test 2 - All ones:")
print(f"Parity: {parity_223_ones.hex()}")

# Test 3: Incrementing pattern
data_223_inc = bytes(range(223))
parity_223_inc = rs_encode(data_223_inc, 32)
print(f"Test 3 - Incrementing:")
print(f"Parity: {parity_223_inc.hex()}")

# Test vectors for RS(255,191)
print("\n=== RS(255,191) Test Vectors ===")

# Test 1: All zeros
data_191_zeros = bytes([0x00] * 191)
parity_191_zeros = rs_encode(data_191_zeros, 64)
print(f"Test 1 - All zeros:")
print(f"Parity: {parity_191_zeros.hex()}")

# Test 2: All ones
data_191_ones = bytes([0xff] * 191)
parity_191_ones = rs_encode(data_191_ones, 64)
print(f"Test 2 - All ones:")
print(f"Parity: {parity_191_ones.hex()}")

# Test 3: Incrementing pattern
data_191_inc = bytes(range(191))
parity_191_inc = rs_encode(data_191_inc, 64)
print(f"Test 3 - Incrementing:")
print(f"Parity: {parity_191_inc.hex()}")

# Test vectors for RS(64,40)
print("\n=== RS(64,40) Test Vectors ===")

# Test 1: All zeros
data_40_zeros = bytes([0x00] * 40)
parity_40_zeros = rs_encode(data_40_zeros, 24)
print(f"Test 1 - All zeros:")
print(f"Parity: {parity_40_zeros.hex()}")

# Test 2: All ones
data_40_ones = bytes([0xff] * 40)
parity_40_ones = rs_encode(data_40_ones, 24)
print(f"Test 2 - All ones:")
print(f"Parity: {parity_40_ones.hex()}")

# Test 3: Incrementing pattern
data_40_inc = bytes(range(40))
parity_40_inc = rs_encode(data_40_inc, 24)
print(f"Test 3 - Incrementing:")
print(f"Parity: {parity_40_inc.hex()}")

# Test vectors for RS(32,10)
print("\n=== RS(32,10) Test Vectors ===")

# Test 1: All zeros
data_10_zeros = bytes([0x00] * 10)
parity_10_zeros = rs_encode(data_10_zeros, 22)
print(f"Test 1 - All zeros:")
print(f"Parity: {parity_10_zeros.hex()}")

# Test 2: All ones
data_10_ones = bytes([0xff] * 10)
parity_10_ones = rs_encode(data_10_ones, 22)
print(f"Test 2 - All ones:")
print(f"Parity: {parity_10_ones.hex()}")

# Test 3: Incrementing pattern
data_10_inc = bytes(range(10))
parity_10_inc = rs_encode(data_10_inc, 22)
print(f"Test 3 - Incrementing:")
print(f"Parity: {parity_10_inc.hex()}")

print("\n=== Verification ===")

def verify_codeword(data, parity):
    """Verify that syndromes are zero for valid codeword."""
    codeword = np.concatenate([GF(list(parity)), GF(list(data))])
    codeword_poly = galois.Poly(codeword[::-1], field=GF)

    parity_len = len(parity)
    syndromes = []
    for i in range(1, parity_len + 1):
        syndrome = codeword_poly(alpha**i)
        syndromes.append(int(syndrome))

    return all(s == 0 for s in syndromes)

test_data = bytes(range(40))
test_parity = rs_encode(test_data, 24)
is_valid = verify_codeword(test_data, test_parity)
print(f"RS(64,40) codeword valid: {is_valid}")
