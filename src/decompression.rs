use std::{fs, fs::File, io::Write, time::Instant};

use libtoa::{TOAFileDecoder, copy_wide};

#[allow(clippy::too_many_arguments)]
pub(crate) fn decompress_file(
    input_path: &str,
    output_path: &str,
    threads: usize,
) -> std::io::Result<(u64, u64, std::time::Duration)> {
    let compressed_size = fs::metadata(input_path)?.len();
    let mut output_file = File::create(output_path)?;

    let mut toa_decoder = TOAFileDecoder::new(input_path, threads, true)?;

    let start_time = Instant::now();

    let decompressed_size = copy_wide(&mut toa_decoder, &mut output_file)?;

    let elapsed = start_time.elapsed();

    Ok((compressed_size, decompressed_size, elapsed))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn test_file(
    input_path: &str,
    threads: usize,
) -> std::io::Result<(u64, u64, std::time::Duration)> {
    let compressed_size = fs::metadata(input_path)?.len();

    let mut toa_decoder = TOAFileDecoder::new(input_path, threads, true)?;

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
