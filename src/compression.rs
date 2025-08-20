use std::{
    fs,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    time::Instant,
};

use libslz::{SLZOptions, SLZStreamingWriter};

use crate::Cli;

fn calculate_block_size_exponent(file_size: u64, block_count: u64) -> Option<u8> {
    if block_count == 0 {
        return None;
    }

    let block_size = file_size.div_ceil(block_count);

    if block_size <= 65536 {
        return Some(16);
    }

    // Find the smallest power of 2 that is >= block_size.
    let log2_size = (64 - block_size.leading_zeros()) as u8;

    // If block_size is already a power of 2, use it as-is, otherwise round up.
    if block_size.is_power_of_two() {
        log2_size - 1
    } else {
        log2_size
    }
    .clamp(16, 62)
    .into()
}

pub(crate) fn compress_file(
    cli: &Cli,
    output_path: &str,
) -> std::io::Result<(u64, u64, std::time::Duration)> {
    let input_file = File::open(&cli.input)?;
    let file_size = input_file.metadata()?.len();
    let mut input_reader = BufReader::with_capacity(65536, input_file);

    let output_file = File::create(output_path)?;
    let output_writer = BufWriter::with_capacity(65536, output_file);

    let mut options = SLZOptions::from_preset(cli.preset);

    let prefilter = cli.get_prefilter()?;
    options = options.with_prefilter(prefilter);

    if let Some(lc) = cli.lc {
        options = options.with_lc(lc);
    }
    if let Some(lp) = cli.lp {
        options = options.with_lp(lp);
    }
    if let Some(pb) = cli.pb {
        options = options.with_pb(pb);
    }
    if let Some(dict_size) = cli.dict_size {
        options = options.with_dictionary_size(dict_size);
    }
    if let Some(block_size) = cli.block_size {
        if block_size == 0 {
            // Block size 0 means maximum block size (single block mode).
            options = options.with_block_size_exponent(None);
        } else {
            options = options.with_block_size_exponent(Some(block_size));
        }
    } else if let Some(block_count) = cli.block_count {
        let calculated_exponent = calculate_block_size_exponent(file_size, block_count);
        options = options.with_block_size_exponent(calculated_exponent);
    } else {
        // Default behavior: set block size to match dictionary size of the selected preset.
        let dict_size_log2 = options.dict_size_log2();
        options = options.with_block_size_exponent(Some(dict_size_log2));
    }

    options = options.with_error_correction(cli.ecc);

    let mut slz_writer = SLZStreamingWriter::new(output_writer, options);

    let start_time = Instant::now();

    let mut buffer = vec![0u8; 65536];
    let mut bytes_read = 0u64;

    loop {
        match input_reader.read(&mut buffer)? {
            0 => break,
            n => {
                slz_writer.write_all(&buffer[..n])?;
                bytes_read += n as u64;
            }
        }
    }
    slz_writer.finish()?;

    let elapsed = start_time.elapsed();

    let compressed_size = fs::metadata(output_path)?.len();

    Ok((bytes_read, compressed_size, elapsed))
}
