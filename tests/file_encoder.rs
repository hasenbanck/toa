use std::{
    fs,
    io::{Cursor, Read},
};

use libtoa::{TOAFileDecoder, TOAFileEncoder, TOAMetadata, TOAOptions, TOAStreamingDecoder};

fn test_encode_with_dict_size(dict_size: u8, expected_blocks: u64) {
    let max_threads = 4;

    let options = TOAOptions::from_preset(1)
        .with_dictionary_exponent(dict_size)
        .with_block_size_exponent(Some(dict_size));

    let mut encoder =
        TOAFileEncoder::new("tests/data/executable.exe", options, max_threads).unwrap();

    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed).unwrap();

    let temp_file_path = format!("tests/data/temp-{}.toa", dict_size);
    fs::write(&temp_file_path, &compressed).unwrap();

    let mut file_decoder = TOAFileDecoder::new(&temp_file_path, max_threads, true).unwrap();
    let mut decompressed_file = Vec::new();
    file_decoder.read_to_end(&mut decompressed_file).unwrap();

    let mut decompressed_streaming = Vec::new();
    let mut streaming_decoder = TOAStreamingDecoder::new(compressed.as_slice(), true);
    streaming_decoder
        .read_to_end(&mut decompressed_streaming)
        .unwrap();

    assert_eq!(decompressed_file, decompressed_streaming);

    let metadata = TOAMetadata::parse(Cursor::new(compressed.as_slice())).unwrap();
    assert_eq!(metadata.block_count, expected_blocks);

    let original_data = fs::read("tests/data/executable.exe").unwrap();
    assert_eq!(decompressed_file, original_data);
    assert_eq!(decompressed_streaming, original_data);

    fs::remove_file(temp_file_path).unwrap();
}

#[test]
fn test_encode_single_blocks() {
    test_encode_with_dict_size(26, 1);
}

#[test]
fn test_encode_multiple_blocks() {
    test_encode_with_dict_size(20, 40);
}
