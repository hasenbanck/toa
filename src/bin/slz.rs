use std::{
    env,
    fs::File,
    io::{self, BufReader, BufWriter, Read, Result, Write},
    process,
    time::Instant,
};

use slz::{SLZOptions, SLZWriter};

fn print_usage() {
    eprintln!("Usage: slz <filename>");
    eprintln!("Compress a file using the SLZ format.");
    eprintln!("Output file will have the same name with .slz extension.");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        print_usage();
        process::exit(1);
    }

    let input_filename = &args[1];

    let output_filename = format!("{input_filename}.slz");

    if let Err(error) = compress_file(input_filename, &output_filename) {
        eprintln!("Error: {error}");
        process::exit(1);
    }

    println!("Compressed {input_filename} into {output_filename}");
}

fn compress_file(input_path: &str, output_path: &str) -> Result<()> {
    let input_file = File::open(input_path)?;
    let file_size = input_file.metadata()?.len();
    let mut input_reader = BufReader::new(input_file);

    let output_file = File::create(output_path)?;
    let output_writer = BufWriter::new(output_file);

    let options = SLZOptions::from_preset(9);

    let mut slz_writer = SLZWriter::new(output_writer, options);

    copy_with_progress(&mut input_reader, &mut slz_writer, file_size)?;

    // Clear progress line
    print!("\r{:<80}\r", "");

    slz_writer.finish()?;

    Ok(())
}

fn copy_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    total_size: u64,
) -> Result<u64> {
    let mut buf = [0; 8192];
    let mut total_copied = 0u64;
    let start_time = Instant::now();
    let mut last_update = Instant::now();

    loop {
        let bytes_read = reader.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }

        writer.write_all(&buf[..bytes_read])?;
        total_copied += bytes_read as u64;

        // Update progress every 100ms
        if last_update.elapsed().as_millis() >= 100 {
            let elapsed = start_time.elapsed();
            let elapsed_secs = elapsed.as_secs_f64();
            let speed_mbs = if elapsed_secs > 0.0 {
                (total_copied as f64) / (1024.0 * 1024.0 * elapsed_secs)
            } else {
                0.0
            };

            let progress_percent = if total_size > 0 {
                (total_copied as f64 / total_size as f64 * 100.0) as u32
            } else {
                0
            };

            print!("\rProgress: {}% ({:.1} MB/s)", progress_percent, speed_mbs);
            io::stdout().flush().unwrap_or(());
            last_update = Instant::now();
        }
    }

    // Final progress update
    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let speed_mbs = if elapsed_secs > 0.0 {
        (total_copied as f64) / (1024.0 * 1024.0 * elapsed_secs)
    } else {
        0.0
    };

    println!("\rProgress: 100% ({:.1} MB/s)", speed_mbs);
    io::stdout().flush().unwrap_or(());

    Ok(total_copied)
}
