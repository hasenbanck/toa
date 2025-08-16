use std::{
    hint::black_box,
    io::{Read, Write},
    ops::Deref,
};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use liblzma::bufread::*;
use slz::{SLZOptions, SLZStreamingReader, SLZStreamingWriter, SliceReader};

static TEST_DATA: &[u8] = include_bytes!("../tests/data/executable.exe");

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");
    group.throughput(Throughput::Bytes(TEST_DATA.len() as u64));
    group.sample_size(25);

    for preset in 0..=9 {
        group.bench_with_input(BenchmarkId::new("slz", preset), &preset, |b, &level| {
            let option = SLZOptions::from_preset(level);

            b.iter(|| {
                let mut slz_compressed = Vec::new();
                let mut writer = SLZStreamingWriter::new(black_box(&mut slz_compressed), option);
                writer
                    .write_all(black_box(TEST_DATA))
                    .expect("write_all failed");
                writer.finish().expect("finished failed");
                black_box(slz_compressed)
            });
        });

        group.bench_with_input(BenchmarkId::new("xz", preset), &preset, |b, &level| {
            b.iter(|| {
                let mut xz_compressed = Vec::new();
                let mut encoder = XzEncoder::new(black_box(TEST_DATA), level);
                encoder
                    .read_to_end(black_box(&mut xz_compressed))
                    .expect("read_to_end failed");
                black_box(xz_compressed)
            });
        });
    }

    group.finish();
}

fn bench_decompression(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression");
    group.throughput(Throughput::Bytes(TEST_DATA.len() as u64));
    group.sample_size(100);

    let mut slz_data = Vec::new();
    let mut xz_data = Vec::new();

    for preset in 0..=9 {
        {
            let option = SLZOptions::from_preset(preset);
            let mut compressed = Vec::new();
            let mut writer = SLZStreamingWriter::new(&mut compressed, option);
            writer.write_all(TEST_DATA).expect("write_all failed");
            writer.finish().expect("finish failed");
            slz_data.push(compressed);
        }

        {
            let mut compressed = Vec::new();
            let mut encoder = XzEncoder::new(TEST_DATA, preset);
            encoder
                .read_to_end(black_box(&mut compressed))
                .expect("read_to_end failed");
            xz_data.push(compressed);
        }
    }

    for level in 0..=9 {
        group.bench_with_input(
            BenchmarkId::new("slz", level),
            &slz_data[level],
            |b, compressed| {
                b.iter(|| {
                    let mut uncompressed = Vec::new();
                    let mut reader = SLZStreamingReader::new(
                        black_box(SliceReader::new(compressed.deref())),
                        true,
                    );
                    reader
                        .read_to_end(black_box(&mut uncompressed))
                        .expect("read_to_end failed");
                    black_box(uncompressed)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("xz", level),
            &xz_data[level],
            |b, compressed| {
                b.iter(|| {
                    let mut uncompressed = Vec::new();
                    let mut r = XzDecoder::new(black_box(compressed.as_slice()));
                    r.read_to_end(black_box(&mut uncompressed))
                        .expect("read_to_end failed");
                    black_box(uncompressed)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, /*bench_compression,*/ bench_decompression,);
criterion_main!(benches);
