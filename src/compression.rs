use std::{
    fs,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    num::NonZeroU64,
    time::Instant,
};

use libslz::{SLZOptions, SLZStreamingWriter};

use crate::Cli;

fn calculate_block_size(file_size: u64, block_count: u64) -> Option<NonZeroU64> {
    if block_count == 0 {
        return None;
    }

    let block_size = file_size.div_ceil(block_count);
    // Align to 1 KiB boundary, ensuring minimum of 1024 bytes
    let aligned_size = ((block_size + 1023) / 1024) * 1024;
    NonZeroU64::new(aligned_size.max(1024))
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
        options = options.with_block_size(NonZeroU64::new(block_size));
    } else if let Some(block_count) = cli.block_count {
        let calculated_block_size = calculate_block_size(file_size, block_count);
        options = options.with_block_size(calculated_block_size);
    }

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
