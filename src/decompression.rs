use std::{fs, fs::File, io::Write, time::Instant};

use libtoa::{TOAFileDecoder, copy_wide};

use crate::Cli;

pub(crate) fn decompress_file(
    cli: &Cli,
    output_path: &str,
) -> std::io::Result<(u64, u64, std::time::Duration)> {
    let compressed_size = fs::metadata(&cli.input)?.len();
    let mut output_file = File::create(output_path)?;

    let mut toa_decoder = TOAFileDecoder::new(&cli.input, cli.threads, true)?;

    let start_time = Instant::now();

    let decompressed_size = copy_wide(&mut toa_decoder, &mut output_file)?;

    let elapsed = start_time.elapsed();

    Ok((compressed_size, decompressed_size, elapsed))
}

pub(crate) fn test_file(cli: &Cli) -> std::io::Result<(u64, u64, std::time::Duration)> {
    let compressed_size = fs::metadata(&cli.input)?.len();

    let mut toa_decoder = TOAFileDecoder::new(&cli.input, cli.threads, true)?;

    let start_time = Instant::now();

    struct NullWriter;

    impl Write for NullWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut null_writer = NullWriter;
    let decompressed_size = copy_wide(&mut toa_decoder, &mut null_writer)?;

    let elapsed = start_time.elapsed();

    Ok((compressed_size, decompressed_size, elapsed))
}
