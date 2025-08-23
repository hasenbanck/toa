use std::io::{Cursor, Read};

use libtoa::{TOAFileEncoder, TOAMetadata, TOAOptions, TOAStreamingDecoder};

fn test_encode_with_dict_size(dict_size: u8, expected_blocks: u64) {
    let max_threads = 4;

    let options = TOAOptions::from_preset(1)
        .with_dictionary_exponent(dict_size)
        .with_block_size_exponent(Some(dict_size));

    let mut encoder = TOAFileEncoder::new("tests/data/wget-sparc", options, max_threads).unwrap();

    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed).unwrap();

    let mut decompressed = Vec::new();
    let mut decoder = TOAStreamingDecoder::new(compressed.as_slice(), true);
    decoder.read_to_end(&mut decompressed).unwrap();

    let metadata = TOAMetadata::parse(Cursor::new(compressed.as_slice())).unwrap();
    assert_eq!(metadata.block_count, expected_blocks);
}

#[test]
fn test_encode_single_blocks() {
    test_encode_with_dict_size(26, 1);
}

#[test]
fn test_encode_multiple_blocks() {
    test_encode_with_dict_size(20, 2);
}
