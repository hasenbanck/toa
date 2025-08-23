use std::{fs, fs::File, time::Instant};

use libtoa::{TOAFileEncoder, TOAOptions, copy_wide};

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
    let file_size = fs::metadata(&cli.input)?.len();
    let mut output_file = File::create(output_path)?;

    let mut options = TOAOptions::from_preset(cli.preset);

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
        options = options.with_dictionary_exponent(dict_size);
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
        // Default behavior: set block size to match dictionary size.
        let dict_size_exponent = options.dict_size_exponent();

        // For very large files slightly larger blocks for better compression.
        let adjusted_block_size = if file_size > (256 << 20) {
            (dict_size_exponent + 1).min(30) // Max 1GB blocks
        } else {
            dict_size_exponent
        };

        options = options.with_block_size_exponent(Some(adjusted_block_size));
    }

    options = options.with_error_correction(cli.ecc);

    let mut toa_encoder = TOAFileEncoder::new(&cli.input, options, cli.threads)?;

    let start_time = Instant::now();

    let compressed_size = copy_wide(&mut toa_encoder, &mut output_file)?;

    let elapsed = start_time.elapsed();

    Ok((file_size, compressed_size, elapsed))
}
