use std::{
    hint::black_box,
    io::{Cursor, Read, Write},
};

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use libtoa::{ECCDecoder, ECCEncoder, ErrorCorrection, SimdOverride};

const DATA_SIZE: usize = 1 << 20;
const BUFFER_SIZE: usize = 64 << 10;

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(0xDA942042E4DD58B5);
        self.0.wrapping_shr(64)
    }

    fn fill_buffer(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let next = self.next_u64();
            let bytes = next.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

fn generate_test_data() -> Vec<u8> {
    let mut lcg = Lcg::new(0x123456789ABCDEF0);
    let mut test_data = vec![0u8; DATA_SIZE];
    lcg.fill_buffer(&mut test_data);
    test_data
}

fn generate_encoded_data(
    error_correction: ErrorCorrection,
    simd_override: SimdOverride,
) -> Vec<u8> {
    let test_data = generate_test_data();

    let mut encoded_output = Vec::new();
    let mut encoder = ECCEncoder::new(&mut encoded_output, error_correction, simd_override);
    encoder.write_all(&test_data).unwrap();
    encoder.finish().unwrap();

    encoded_output
}

fn get_benchmark_name(error_correction: ErrorCorrection, simd_override: SimdOverride) -> String {
    let ec_name = match error_correction {
        ErrorCorrection::None => "none",
        ErrorCorrection::Standard => "standard",
        ErrorCorrection::Paranoid => "paranoid",
        ErrorCorrection::Extreme => "extreme",
    };

    let simd_name = match simd_override {
        SimdOverride::Auto => "auto",
        SimdOverride::ForceScalar => "scalar",
        #[cfg(target_arch = "x86_64")]
        SimdOverride::ForceSsse3 => "ssse3",
        #[cfg(target_arch = "x86_64")]
        SimdOverride::ForceAvx2 => "avx2",
        #[cfg(target_arch = "x86_64")]
        SimdOverride::ForceAvx2Gfni => "avx2_gfni",
        #[cfg(target_arch = "aarch64")]
        SimdOverride::ForceNeon => "neon",
    };

    format!("{ec_name}_{simd_name}")
}

fn check_simd_support(simd_override: SimdOverride, bench_name: &str) -> bool {
    #[cfg(target_arch = "x86_64")]
    match simd_override {
        SimdOverride::ForceSsse3 if !is_x86_feature_detected!("ssse3") => {
            eprintln!("Skipping {bench_name}: SSSE3 not available");
            return false;
        }
        SimdOverride::ForceAvx2 if !is_x86_feature_detected!("avx2") => {
            eprintln!("Skipping {bench_name}: AVX2 not available");
            return false;
        }
        SimdOverride::ForceAvx2Gfni
            if !is_x86_feature_detected!("avx2") || !is_x86_feature_detected!("gfni") =>
        {
            eprintln!("Skipping {bench_name}: AVX2+GFNI not available");
            return false;
        }
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match simd_override {
        SimdOverride::ForceNeon if !std::arch::is_aarch64_feature_detected!("neon") => {
            eprintln!("Skipping {bench_name}: NEON not available");
            return false;
        }
        _ => {}
    }

    true
}

fn bench_ecc_encoder(
    group: &mut BenchmarkGroup<WallTime>,
    error_correction: ErrorCorrection,
    simd_override: SimdOverride,
) {
    let bench_name = get_benchmark_name(error_correction, simd_override);

    if !check_simd_support(simd_override, &bench_name) {
        return;
    }

    let test_data = generate_test_data();
    let throughput = Throughput::Bytes(test_data.len() as u64);
    group.throughput(throughput);

    group.bench_with_input(
        BenchmarkId::new("encode", bench_name),
        &test_data,
        |b, test_data| {
            b.iter(|| {
                let mut encoded_output = Vec::new();
                let mut encoder =
                    ECCEncoder::new(&mut encoded_output, error_correction, simd_override);

                for chunk in test_data.chunks(BUFFER_SIZE) {
                    encoder.write_all(chunk).expect("Write should succeed");
                }

                let encoded = encoder.finish().expect("Finish should succeed");
                black_box(encoded);
            });
        },
    );
}

fn bench_ecc_decoder(
    group: &mut BenchmarkGroup<WallTime>,
    error_correction: ErrorCorrection,
    simd_override: SimdOverride,
) {
    let bench_name = get_benchmark_name(error_correction, simd_override);

    if !check_simd_support(simd_override, &bench_name) {
        return;
    }

    let encoded_data = generate_encoded_data(error_correction, simd_override);
    let throughput = Throughput::Bytes(encoded_data.len() as u64);
    group.throughput(throughput);

    group.bench_with_input(
        BenchmarkId::new("decode", bench_name),
        &encoded_data,
        |b, encoded_data| {
            b.iter(|| {
                let cursor = Cursor::new(encoded_data);
                let mut decoder = ECCDecoder::new(cursor, error_correction, true, simd_override);
                let mut decoded_output = Vec::new();
                let mut buffer = vec![0u8; BUFFER_SIZE];

                loop {
                    match decoder.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(bytes_read) => {
                            decoded_output.extend_from_slice(&buffer[..bytes_read]);
                        }
                        Err(error) => panic!("Decoder error: {error}"),
                    }
                    black_box(buffer.as_slice());
                }

                black_box(buffer.as_slice());
            });
        },
    );
}

fn get_test_configurations() -> (Vec<ErrorCorrection>, Vec<SimdOverride>) {
    let error_corrections = vec![
        ErrorCorrection::Standard,
        ErrorCorrection::Paranoid,
        ErrorCorrection::Extreme,
    ];

    let simd_overrides = vec![
        SimdOverride::ForceScalar,
        SimdOverride::Auto,
        #[cfg(target_arch = "x86_64")]
        SimdOverride::ForceSsse3,
        #[cfg(target_arch = "x86_64")]
        SimdOverride::ForceAvx2,
        #[cfg(target_arch = "x86_64")]
        SimdOverride::ForceAvx2Gfni,
        #[cfg(target_arch = "aarch64")]
        SimdOverride::ForceNeon,
    ];

    (error_corrections, simd_overrides)
}

fn benchmark_ecc_encoder_all(c: &mut Criterion) {
    let (error_corrections, simd_overrides) = get_test_configurations();

    let mut group = c.benchmark_group("ecc_encoder");

    for &error_correction in &error_corrections {
        for &simd_override in &simd_overrides {
            bench_ecc_encoder(&mut group, error_correction, simd_override);
        }
    }

    group.finish();
}

fn benchmark_ecc_decoder_all(c: &mut Criterion) {
    let (error_corrections, simd_overrides) = get_test_configurations();

    let mut group = c.benchmark_group("ecc_decoder");

    for &error_correction in &error_corrections {
        for &simd_override in &simd_overrides {
            bench_ecc_decoder(&mut group, error_correction, simd_override);
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_ecc_encoder_all,
    benchmark_ecc_decoder_all
);
criterion_main!(benches);
