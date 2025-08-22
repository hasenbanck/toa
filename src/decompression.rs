use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    time::Instant,
};

use libtoa::TOAStreamingReader;

use crate::Cli;

pub(crate) fn decompress_file(
    cli: &Cli,
    output_path: &str,
) -> std::io::Result<(u64, u64, std::time::Duration)> {
    let input_file = File::open(&cli.input)?;
    let compressed_size = input_file.metadata()?.len();

    let reader = BufReader::with_capacity(64 << 10, input_file);
    let mut toa_reader = TOAStreamingReader::new(reader, true);

    let output_file = File::create(output_path)?;
    let mut output_writer = BufWriter::with_capacity(64 << 10, output_file);

    let start_time = Instant::now();

    let mut buffer = vec![0u8; 64 << 10];
    let mut total_written = 0u64;

    loop {
        match toa_reader.read(&mut buffer)? {
            0 => break,
            n => {
                output_writer.write_all(&buffer[..n])?;
                total_written += n as u64;
            }
        }
    }

    output_writer.flush()?;
    let elapsed = start_time.elapsed();

    Ok((compressed_size, total_written, elapsed))
}
