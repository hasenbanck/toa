use std::io::{Read, Write};

use libslz::{
    SLZFileTrailer, SLZOptions, SLZStreamingReader, SLZStreamingWriter,
    optimized_reader::SliceReader,
};

fn compress_and_get_slz_hash(
    data: &[u8],
    block_size: u8,
) -> Result<String, Box<dyn std::error::Error>> {
    let block_size_exp = block_size + 10;
    let options = SLZOptions::from_preset(3).with_block_size_exponent(Some(block_size_exp));

    let mut compressed_data = Vec::new();
    {
        let mut writer = SLZStreamingWriter::new(&mut compressed_data, options);
        writer.write_all(data)?;
        writer.finish()?;
    }

    {
        let mut uncompressed_data = Vec::new();
        let mut reader = SLZStreamingReader::new(SliceReader::new(compressed_data.as_ref()), true);
        reader.read_to_end(&mut uncompressed_data)?;
        assert_eq!(uncompressed_data.as_slice(), data);
    }

    let mut trailer_array = [0u8; 64];
    let trailer_start = compressed_data.len() - 64;
    trailer_array.copy_from_slice(&compressed_data[trailer_start..]);

    let trailer = SLZFileTrailer::parse(&trailer_array, false)?;
    let hash_bytes = trailer.blake3_hash();

    let hash_hex = hash_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(hash_hex)
}

/// Test specific block count case
fn test_block_count_case(expected_hash: &str, file_size: usize, block_size: u8, pattern: u8) {
    let data = vec![pattern; file_size];

    let actual_hash =
        compress_and_get_slz_hash(&data, block_size).expect("SLZ compression should succeed");

    assert_eq!(
        actual_hash, expected_hash,
        "Hash mismatch - SLZ: {}, expected: {}",
        actual_hash, expected_hash
    );
}

#[test]
fn test_single_block() {
    // Single block: 32KB file with 64KB blocks
    test_block_count_case(
        "848eb396076028fdfe1133c3078e4541817f76461d27163adbfc82a55363aee1",
        32 * 1024,
        16,
        0x42,
    );
}

#[test]
fn test_two_blocks_power_of_2() {
    // Two blocks (power of 2): 128KB file with 64KB blocks
    test_block_count_case(
        "2abdf8fb89c3df201cc4c4d33bdf58a094126177f5820ac9f9b40000468d2d09",
        128 * 1024,
        16,
        0x43,
    );
}

#[test]
fn test_three_blocks() {
    // Three blocks: 192KB file with 64KB blocks
    test_block_count_case(
        "0b6310de56f0483e8175e9b4d30e14123e526959b56b55ba3d803d46a0a7f72e",
        192 * 1024,
        16,
        0x44,
    );
}

#[test]
fn test_four_blocks_power_of_2() {
    // Four blocks (power of 2): 256KB file with 64KB blocks
    test_block_count_case(
        "999251bdbb729527f92296cd57309ee8548f5bdeb85952f970e55e7573e49c91",
        256 * 1024,
        16,
        0x45,
    );
}

#[test]
fn test_five_blocks() {
    // Five blocks: 320KB file with 64KB blocks
    test_block_count_case(
        "6dc0f6e4fe1c61290891ff698bdb4fecd4b7138f7dba6587daf93a717e35f830",
        320 * 1024,
        16,
        0x46,
    );
}

#[test]
fn test_eight_blocks_power_of_2() {
    // Eight blocks (power of 2): 512KB file with 64KB blocks
    test_block_count_case(
        "303af5f1fb59ac7b2f654d87544b6b7ffd40b1b269916bcfe310ac25977d5b5c",
        512 * 1024,
        16,
        0x47,
    );
}

#[test]
fn test_sixteen_blocks_power_of_2() {
    // Sixteen blocks (power of 2): 1MB file with 64KB blocks
    test_block_count_case(
        "544f851259a35e14f6db263bec303018931571071820a691207189ec537288e2",
        1024 * 1024,
        16,
        0x48,
    );
}

#[test]
fn test_partial_final_block() {
    // Non-aligned size: 200KB file with 64KB blocks (3.125 blocks)
    test_block_count_case(
        "11d18712ed9237e3492805542aa2600d6ad339d14c3095ec136ce0c2c884473d",
        200 * 1024,
        16,
        0x49,
    );
}

#[test]
fn test_small_blocks_many_count() {
    // Many small blocks: 260KB file with 64KB blocks (just over 4 blocks)
    test_block_count_case(
        "e35d464de3144ea508a4944dbb89b3017d41efa76ff840dee6fa117be46e615a",
        260 * 1024,
        16,
        0x4A,
    );
}

#[test]
fn test_edge_case_exactly_two_blocks() {
    // Exactly 2 blocks: 131072 bytes with 64KB blocks
    test_block_count_case(
        "15741f4c1583214c8dc575bc7e2849c6d3728583f81f67c7524d4fdc5ec18f87",
        2 * 65536,
        16,
        0x4B,
    );
}
