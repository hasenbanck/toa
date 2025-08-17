use std::{
    fs,
    io::{Cursor, Read, Write},
};

use libslz::{Prefilter, SLZOptions, SLZStreamingReader, SLZStreamingWriter};

struct LZMAParameter {
    lc: u8,
    lp: u8,
    pb: u8,
}

fn test_bcj_filter_roundtrip(
    test_data: &[u8],
    prefilter: Prefilter,
    parameter: Option<LZMAParameter>,
    test_name: &str,
) {
    let mut options_bcj = SLZOptions::from_preset(6).with_prefilter(prefilter);
    let mut options_no_bcj = SLZOptions::from_preset(6).with_prefilter(Prefilter::None);

    if let Some(parameter) = parameter {
        options_bcj = options_bcj
            .with_lc(parameter.lc)
            .with_lp(parameter.lp)
            .with_pb(parameter.pb);

        options_no_bcj = options_no_bcj
            .with_lc(parameter.lc)
            .with_lp(parameter.lp)
            .with_pb(parameter.pb);
    }

    // Compress with BCJ + LZMA
    let mut compressed_data_bcj = Vec::new();
    {
        let cursor = Cursor::new(&mut compressed_data_bcj);
        let mut writer = SLZStreamingWriter::new(cursor, options_bcj);
        writer
            .write_all(test_data)
            .unwrap_or_else(|_| panic!("Failed to write data for {test_name}"));
        writer
            .finish()
            .unwrap_or_else(|_| panic!("Failed to finish compression for {test_name}"));
    }

    // Compress with LZMA only (no prefilter)
    let mut compressed_data_no_bcj = Vec::new();
    {
        let cursor = Cursor::new(&mut compressed_data_no_bcj);
        let mut writer = SLZStreamingWriter::new(cursor, options_no_bcj);
        writer
            .write_all(test_data)
            .unwrap_or_else(|_| panic!("Failed to write data for {test_name} (no BCJ)"));
        writer
            .finish()
            .unwrap_or_else(|_| panic!("Failed to finish compression for {test_name} (no BCJ)"));
    }

    assert!(
        !compressed_data_bcj.is_empty(),
        "No compressed data generated for {test_name}"
    );

    assert!(
        !compressed_data_no_bcj.is_empty(),
        "No compressed data generated for {test_name} (no BCJ)"
    );

    assert!(
        compressed_data_bcj.len() < compressed_data_no_bcj.len(),
        "BCJ + LZMA should be more efficient than LZMA only for {test_name}: BCJ+LZMA={} bytes, LZMA-only={} bytes",
        compressed_data_bcj.len(),
        compressed_data_no_bcj.len()
    );

    let mut decompressed_data = Vec::new();
    {
        let cursor = Cursor::new(compressed_data_bcj);
        let reader = libslz::BufferedReader::new(cursor)
            .unwrap_or_else(|_| panic!("Failed to create buffered reader for {test_name}"));
        let mut slz_reader = SLZStreamingReader::new(reader, true);

        let mut buffer = vec![0u8; 8192];
        loop {
            match slz_reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => decompressed_data.extend_from_slice(&buffer[..n]),
                Err(error) => panic!("Failed to read decompressed data for {test_name}: {error}"),
            }
        }
    }

    assert_eq!(
        test_data.len(),
        decompressed_data.len(),
        "Decompressed size mismatch for {}: expected {}, got {}",
        test_name,
        test_data.len(),
        decompressed_data.len()
    );

    assert_eq!(
        test_data,
        decompressed_data.as_slice(),
        "Decompressed data doesn't match original for {test_name}"
    );
}

fn load_test_data(filename: &str) -> Vec<u8> {
    let path = format!("tests/data/{}", filename);
    fs::read(&path).unwrap_or_else(|_| panic!("Failed to read test file: {path}"))
}

#[test]
fn test_bcj_x86_filter() {
    let test_data = load_test_data("wget-x86");
    test_bcj_filter_roundtrip(&test_data, Prefilter::BcjX86, None, "BCJ x86");
}

#[test]
fn test_bcj_arm_filter() {
    let test_data = load_test_data("wget-arm");
    test_bcj_filter_roundtrip(
        &test_data,
        Prefilter::BcjArm,
        Some(LZMAParameter {
            lc: 2,
            lp: 2,
            pb: 2,
        }),
        "BCJ ARM",
    );
}

#[test]
fn test_bcj_arm_thumb_filter() {
    let test_data = load_test_data("wget-arm-thumb");
    test_bcj_filter_roundtrip(
        &test_data,
        Prefilter::BcjArmThumb,
        Some(LZMAParameter {
            lc: 2,
            lp: 2,
            pb: 2,
        }),
        "BCJ ARM Thumb",
    );
}

#[test]
fn test_bcj_arm64_filter() {
    let test_data = load_test_data("wget-arm64");
    test_bcj_filter_roundtrip(
        &test_data,
        Prefilter::BcjArm64,
        Some(LZMAParameter {
            lc: 2,
            lp: 2,
            pb: 2,
        }),
        "BCJ ARM64",
    );
}

#[test]
fn test_bcj_sparc_filter() {
    let test_data = load_test_data("wget-sparc");
    test_bcj_filter_roundtrip(&test_data, Prefilter::BcjSparc, None, "BCJ SPARC");
}

#[test]
fn test_bcj_powerpc_filter() {
    let test_data = load_test_data("wget-ppc");
    test_bcj_filter_roundtrip(&test_data, Prefilter::BcjPowerPc, None, "BCJ PowerPC");
}

#[test]
fn test_bcj_ia64_filter() {
    let test_data = load_test_data("wget-ia64");
    test_bcj_filter_roundtrip(
        &test_data,
        Prefilter::BcjIa64,
        Some(LZMAParameter {
            lc: 0,
            lp: 4,
            pb: 4,
        }),
        "BCJ IA-64",
    );
}

#[test]
fn test_bcj_riscv_filter() {
    let test_data = load_test_data("wget-riscv");
    test_bcj_filter_roundtrip(
        &test_data,
        Prefilter::BcjRiscV,
        Some(LZMAParameter {
            lc: 2,
            lp: 2,
            pb: 2,
        }),
        "BCJ RISC-V",
    );
}
