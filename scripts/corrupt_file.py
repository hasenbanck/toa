#!/usr/bin/env python3
"""
TOA file corruption script for testing Reed-Solomon error correction.

This script parses TOA file structure and applies the maximum correctable
number of random byte errors to each component within its ECC capability.
"""
import sys
import random
import os
from typing import List, Tuple

# TOA file format constants.
TOA_MAGIC = b'\xFE\xDC\xBA\x98'
HEADER_SIZE = 32
BLOCK_HEADER_SIZE = 64
TRAILER_SIZE = 64

# Reed-Solomon correction capabilities (in bytes).
RS_32_10_MAX_ERRORS = 11   # File header
RS_64_40_MAX_ERRORS = 12   # Block headers and trailer
RS_255_239_MAX_ERRORS = 8  # Standard data protection
RS_255_223_MAX_ERRORS = 16 # Paranoid data protection
RS_255_191_MAX_ERRORS = 32 # Extreme data protection

# Error correction levels from capabilities field.
ECC_NONE = 0b00
ECC_STANDARD = 0b01
ECC_PARANOID = 0b10
ECC_EXTREME = 0b11

ECC_NAMES = {
    ECC_NONE: "None",
    ECC_STANDARD: "Standard (RS 255,239)",
    ECC_PARANOID: "Paranoid (RS 255,223)",
    ECC_EXTREME: "Extreme (RS 255,191)",
}

ECC_MAX_ERRORS = {
    ECC_NONE: 0,
    ECC_STANDARD: RS_255_239_MAX_ERRORS,
    ECC_PARANOID: RS_255_223_MAX_ERRORS,
    ECC_EXTREME: RS_255_191_MAX_ERRORS,
}


def parse_toa_header(data: bytearray) -> Tuple[int, int]:
    """
    Parse TOA file header and extract error correction level.

    Returns: (ecc_level, block_size_exponent)
    """
    if len(data) < HEADER_SIZE:
        raise ValueError("File too small to contain header")

    magic = bytes(data[0:4])
    if magic != TOA_MAGIC:
        raise ValueError(f"Invalid TOA magic bytes: {magic.hex()}")

    version = data[4]
    if version != 0x01:
        raise ValueError(f"Unsupported TOA version: {version}")

    capabilities = data[5]
    ecc_level = capabilities & 0b11

    block_size_exponent = data[7]

    return ecc_level, block_size_exponent


def parse_blocks(data: bytearray, offset: int) -> List[Tuple[int, int]]:
    """
    Parse block headers and return list of (header_offset, data_size) tuples.

    Returns when the trailer is detected (MSB=1 in first byte).
    """
    blocks = []
    current_offset = offset

    while current_offset < len(data):
        if current_offset + BLOCK_HEADER_SIZE > len(data):
            raise ValueError(f"Incomplete block header at offset {current_offset}")

        # Check MSB of first byte to distinguish block header (0) from trailer (1)
        first_byte = data[current_offset]
        is_trailer = (first_byte & 0x80) != 0

        if is_trailer:
            # This is the final trailer, stop parsing blocks
            break

        # Parse physical size (big-endian, bits 2-63)
        size_bytes = data[current_offset:current_offset + 8]
        physical_size_with_flags = int.from_bytes(size_bytes, byteorder='big')

        # Mask out the flag bits (top 2 bits)
        physical_size = physical_size_with_flags & ~(0b11 << 62)

        blocks.append((current_offset, physical_size))

        # Move to next block: skip header + data
        current_offset += BLOCK_HEADER_SIZE + physical_size

    return blocks


def apply_errors_to_region(data: bytearray, start: int, length: int,
                           max_errors: int, region_name: str) -> int:
    """
    Apply random byte errors to a region, up to max_errors.

    Returns the number of errors applied.
    """
    if max_errors == 0 or length == 0:
        return 0

    # Apply maximum correctable errors
    num_errors = min(max_errors, length)

    # Select random positions within the region
    positions = random.sample(range(start, start + length), num_errors)

    for pos in positions:
        original_byte = data[pos]
        new_byte = random.randint(0, 255)
        # Ensure we actually change the byte
        while new_byte == original_byte:
            new_byte = random.randint(0, 255)
        data[pos] = new_byte

    return num_errors


def apply_errors_to_data_blocks(data: bytearray, blocks: List[Tuple[int, int]],
                                ecc_level: int) -> int:
    """
    Apply errors to compressed data blocks based on ECC level.

    For each 255-byte codeword, apply maximum correctable errors.
    """
    max_errors_per_codeword = ECC_MAX_ERRORS[ecc_level]

    if max_errors_per_codeword == 0:
        print("  Data blocks: No ECC protection, skipping")
        return 0

    total_errors = 0

    for block_idx, (header_offset, data_size) in enumerate(blocks):
        data_start = header_offset + BLOCK_HEADER_SIZE
        data_end = data_start + data_size

        # Process data in 255-byte codewords.
        codeword_start = data_start
        codeword_num = 0

        while codeword_start < data_end:
            codeword_end = min(codeword_start + 255, data_end)
            codeword_length = codeword_end - codeword_start

            num_errors = apply_errors_to_region(
                data, codeword_start, codeword_length,
                max_errors_per_codeword,
                f"Block {block_idx} codeword {codeword_num}"
            )
            total_errors += num_errors

            codeword_start = codeword_end
            codeword_num += 1

    return total_errors


def corrupt_toa_file(filepath: str):
    """
    Main corruption function that parses TOA structure and applies errors.
    """
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    if len(data) == 0:
        raise ValueError("File is empty")

    print(f"Parsing TOA file: {filepath}")
    print(f"File size: {len(data)} bytes")

    # Parse header.
    ecc_level, block_size_exp = parse_toa_header(data)
    block_size = 2 ** block_size_exp

    print(f"ECC Level: {ECC_NAMES[ecc_level]}")
    print(f"Block size: 2^{block_size_exp} = {block_size} bytes")
    print()

    # Parse blocks.
    blocks = parse_blocks(data, HEADER_SIZE)
    print(f"Found {len(blocks)} block(s)")

    # Calculate trailer offset.
    if len(blocks) > 0:
        last_block_header, last_block_size = blocks[-1]
        trailer_offset = last_block_header + BLOCK_HEADER_SIZE + last_block_size
    else:
        trailer_offset = HEADER_SIZE

    if trailer_offset + TRAILER_SIZE > len(data):
        raise ValueError(f"Trailer expected at offset {trailer_offset} but file ends at {len(data)}")

    total_errors = 0

    # Corrupt file header.
    errors = apply_errors_to_region(data, 0, HEADER_SIZE, RS_32_10_MAX_ERRORS, "File header")
    total_errors += errors

    # Corrupt block headers.
    for idx, (header_offset, _) in enumerate(blocks):
        errors = apply_errors_to_region(
            data, header_offset, BLOCK_HEADER_SIZE,
            RS_64_40_MAX_ERRORS, f"Block {idx} header"
        )
        total_errors += errors

    # Corrupt data blocks based on ECC level.
    errors = apply_errors_to_data_blocks(data, blocks, ecc_level)
    total_errors += errors

    # Corrupt trailer.
    errors = apply_errors_to_region(
        data, trailer_offset, TRAILER_SIZE,
        RS_64_40_MAX_ERRORS, "File trailer"
    )
    total_errors += errors

    # Write corrupted file.
    base, ext = os.path.splitext(filepath)
    output_file = f"{base}_corrupted{ext}"

    with open(output_file, 'wb') as f:
        f.write(data)

    print()
    print(f"Total errors applied: {total_errors}")
    print(f"Corrupted file saved as: {output_file}")
    print()
    print("All errors are within Reed-Solomon correction capabilities.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python corrupt_file.py <toa_filepath>")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)

    try:
        corrupt_toa_file(filepath)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
