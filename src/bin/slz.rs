use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Result, Write},
    num::NonZeroU64,
    process,
    time::Instant,
};

use clap::{Arg, ArgMatches, Command, value_parser};
use slz::{
    BufferedReader, Prefilter, SLZMetadata, SLZOptions, SLZStreamingReader, SLZStreamingWriter,
};

struct Cli {
    input: String,
    output: Option<String>,
    extract: bool,
    list: bool,
    keep: bool,
    preset: u32,
    block_size: Option<u64>,
    x86: bool,
    arm: bool,
    armthumb: bool,
    arm64: bool,
    sparc: bool,
    powerpc: bool,
    ia64: bool,
    riscv: bool,
    delta: Option<u16>,
    lc: Option<u8>,
    lp: Option<u8>,
    pb: Option<u8>,
    dict_size: Option<u8>,
}

impl Cli {
    fn build_command() -> Command {
        Command::new("slz")
            .about("Compress and decompress files using the SLZ (Streaming LZMA) format")
            .version(env!("CARGO_PKG_VERSION"))
            .arg(
                Arg::new("input")
                    .help("Input file to compress or decompress")
                    .value_name("FILE")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::new("extract")
                    .help("Decompress/extract the input file")
                    .short('d')
                    .long("decompress")
                    .alias("extract")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("list")
                    .help("List information about the SLZ file")
                    .short('l')
                    .long("list")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("keep")
                    .help("Keep input file after compression/decompression")
                    .short('k')
                    .long("keep")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("output")
                    .help("Output file path (defaults to input + .slz for compression, or input without .slz for extraction)")
                    .short('o')
                    .long("output")
                    .value_name("FILE"),
            )
            .arg(
                Arg::new("preset")
                    .help("Compression preset level (0-9, higher is better compression)")
                    .short('p')
                    .long("preset")
                    .value_parser(value_parser!(u32).range(0..=9))
                    .default_value("6"),
            )
            .arg(
                Arg::new("block-size")
                    .help("Block size in uncompressed bytes")
                    .long("block-size")
                    .value_name("bytes")
                    .value_parser(value_parser!(u64).range(1..=18446744073709551615)),
            )
            .arg(
                Arg::new("x86")
                    .help("Use x86 BCJ filter")
                    .long("x86")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("arm")
                    .help("Use ARM BCJ filter")
                    .long("arm")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("armthumb")
                    .help("Use ARM Thumb BCJ filter")
                    .long("armthumb")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("arm64")
                    .help("Use ARM64 BCJ filter")
                    .long("arm64")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("sparc")
                    .help("Use SPARC BCJ filter")
                    .long("sparc")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("powerpc")
                    .help("Use PowerPC BCJ filter")
                    .long("powerpc")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("ia64")
                    .help("Use IA-64 BCJ filter")
                    .long("ia64")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("riscv")
                    .help("Use RISC-V BCJ filter")
                    .long("riscv")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("delta")
                    .help("Use Delta filter with specified distance (1-256)")
                    .long("delta")
                    .value_name("distance")
                    .value_parser(value_parser!(u16)),
            )
            .arg(
                Arg::new("lc")
                    .help("LZMA literal context bits (0-8)")
                    .long("lc")
                    .value_parser(value_parser!(u8).range(0..=8)),
            )
            .arg(
                Arg::new("lp")
                    .help("LZMA literal position bits (0-4)")
                    .long("lp")
                    .value_parser(value_parser!(u8).range(0..=4)),
            )
            .arg(
                Arg::new("pb")
                    .help("LZMA position bits (0-4)")
                    .long("pb")
                    .value_parser(value_parser!(u8).range(0..=4)),
            )
            .arg(
                Arg::new("dict-size")
                    .help("Dictionary size as power of 2 (16-30, e.g., 26 = 64MiB)")
                    .long("dict-size")
                    .value_name("N")
                    .value_parser(value_parser!(u8).range(16..=30)),
            )
    }

    fn from_matches(matches: &ArgMatches) -> Self {
        Self {
            input: matches.get_one::<String>("input").unwrap().clone(),
            output: matches.get_one::<String>("output").cloned(),
            extract: matches.get_flag("extract"),
            list: matches.get_flag("list"),
            keep: matches.get_flag("keep"),
            preset: *matches.get_one::<u32>("preset").unwrap(),
            block_size: matches.get_one::<u64>("block-size").copied(),
            x86: matches.get_flag("x86"),
            arm: matches.get_flag("arm"),
            armthumb: matches.get_flag("armthumb"),
            arm64: matches.get_flag("arm64"),
            sparc: matches.get_flag("sparc"),
            powerpc: matches.get_flag("powerpc"),
            ia64: matches.get_flag("ia64"),
            riscv: matches.get_flag("riscv"),
            delta: matches.get_one::<u16>("delta").copied(),
            lc: matches.get_one::<u8>("lc").copied(),
            lp: matches.get_one::<u8>("lp").copied(),
            pb: matches.get_one::<u8>("pb").copied(),
            dict_size: matches.get_one::<u8>("dict-size").copied(),
        }
    }

    fn get_prefilter(&self) -> Result<Prefilter> {
        let mut filters = Vec::new();

        if self.x86 {
            filters.push("x86");
        }
        if self.arm {
            filters.push("arm");
        }
        if self.armthumb {
            filters.push("armthumb");
        }
        if self.arm64 {
            filters.push("arm64");
        }
        if self.sparc {
            filters.push("sparc");
        }
        if self.powerpc {
            filters.push("powerpc");
        }
        if self.ia64 {
            filters.push("ia64");
        }
        if self.riscv {
            filters.push("riscv");
        }
        if self.delta.is_some() {
            filters.push("delta");
        }

        if filters.len() > 1 {
            eprintln!(
                "Error: Only one prefilter can be specified at a time: {}",
                filters.join(", ")
            );
            process::exit(1);
        }

        Ok(match filters.first() {
            Some(&"x86") => Prefilter::BcjX86,
            Some(&"arm") => Prefilter::BcjArm,
            Some(&"armthumb") => Prefilter::BcjArmThumb,
            Some(&"arm64") => Prefilter::BcjArm64,
            Some(&"sparc") => Prefilter::BcjSparc,
            Some(&"powerpc") => Prefilter::BcjPowerPc,
            Some(&"ia64") => Prefilter::BcjIa64,
            Some(&"riscv") => Prefilter::BcjRiscV,
            Some(&"delta") => Prefilter::Delta {
                distance: self.delta.unwrap_or(1).clamp(1, 256),
            },
            None => Prefilter::None,
            _ => unreachable!(),
        })
    }
}

fn main() -> Result<()> {
    let matches = Cli::build_command().get_matches();
    let cli = Cli::from_matches(&matches);

    if cli.list {
        // List mode - show metadata
        if let Err(error) = list_file_info(&cli) {
            eprintln!("Error: {error}");
            process::exit(1);
        }
    } else if cli.extract {
        // Extraction mode
        let output_filename = cli.output.clone().unwrap_or_else(|| {
            if cli.input.ends_with(".slz") {
                cli.input[..cli.input.len() - 4].to_string()
            } else {
                format!("{}.extracted", cli.input)
            }
        });

        let (compressed_size, uncompressed_size, elapsed) =
            match decompress_file(&cli, &output_filename) {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("Error: {error}");
                    process::exit(1);
                }
            };

        let speed_mibs = if elapsed.as_secs_f64() > 0.0 {
            (uncompressed_size as f64) / (1024.0 * 1024.0 * elapsed.as_secs_f64())
        } else {
            0.0
        };

        println!("Compressed:   {compressed_size} bytes");
        println!("Uncompressed: {uncompressed_size} bytes");
        println!(
            "Compression ratio: {:.2}% bytes",
            if uncompressed_size > 0 {
                (compressed_size as f64 / uncompressed_size as f64) * 100.0
            } else {
                0.0
            },
        );
        println!("Decompression time: {:.3}s", elapsed.as_secs_f64(),);
        println!("Decompression speed: {speed_mibs:.1} MiB/s");

        if !cli.keep
            && let Err(error) = remove_input_file(&cli.input)
        {
            eprintln!("Warning: Failed to remove input file: {error}");
        }
    } else {
        // Compression mode
        let output_filename = cli
            .output
            .clone()
            .unwrap_or_else(|| format!("{}.slz", cli.input));

        let (uncompressed_size, compressed_size, elapsed) =
            match compress_file(&cli, &output_filename) {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("Error: {error}");
                    process::exit(1);
                }
            };

        let speed_mibs = if elapsed.as_secs_f64() > 0.0 {
            (uncompressed_size as f64) / (1024.0 * 1024.0 * elapsed.as_secs_f64())
        } else {
            0.0
        };

        println!("Compressed:   {compressed_size} bytes");
        println!("Uncompressed: {uncompressed_size} bytes");
        println!(
            "Compression ratio: {:.2}% bytes",
            if uncompressed_size > 0 {
                (compressed_size as f64 / uncompressed_size as f64) * 100.0
            } else {
                0.0
            },
        );
        println!("Compression time: {:.3}s", elapsed.as_secs_f64(),);
        println!("Compression speed: {speed_mibs:.1} MiB/s");

        if !cli.keep
            && let Err(error) = remove_input_file(&cli.input)
        {
            eprintln!("Warning: Failed to remove input file: {error}");
        }
    }

    Ok(())
}

fn compress_file(cli: &Cli, output_path: &str) -> Result<(u64, u64, std::time::Duration)> {
    let input_file = File::open(&cli.input)?;
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

fn decompress_file(cli: &Cli, output_path: &str) -> Result<(u64, u64, std::time::Duration)> {
    let input_file = File::open(&cli.input)?;
    let compressed_size = input_file.metadata()?.len();

    let reader = BufferedReader::new(input_file)?;
    let mut slz_reader = SLZStreamingReader::new(reader, true);

    let output_file = File::create(output_path)?;
    let mut output_writer = BufWriter::with_capacity(65536, output_file);

    let start_time = Instant::now();

    let mut buffer = vec![0u8; 65536];
    let mut total_written = 0u64;

    loop {
        match slz_reader.read(&mut buffer)? {
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

fn remove_input_file(input_path: &str) -> Result<()> {
    fs::remove_file(input_path)?;
    Ok(())
}

fn list_file_info(cli: &Cli) -> Result<()> {
    let input_file = File::open(&cli.input)?;
    let metadata = SLZMetadata::parse(input_file)?;

    println!("Archive: {}", cli.input);
    println!("  Format version: 1");
    println!("  Prefilter: {}", format_prefilter(&metadata.prefilter));
    println!("  LZMA properties:");
    println!("    Literal context bits (lc): {}", metadata.lc);
    println!("    Literal position bits (lp): {}", metadata.lp);
    println!("    Position bits (pb): {}", metadata.pb);
    println!(
        "    Dictionary size: {} bytes ({:.1} MiB)",
        metadata.dict_size,
        metadata.dict_size as f64 / (1024.0 * 1024.0)
    );
    println!("  Structure:");
    println!("    Block count: {}", metadata.block_count);
    if metadata.block_count > 0 {
        let avg_block_size = metadata.compressed_size / metadata.block_count as u64;
        println!(
            "    Average block size: {} bytes ({:.1} KiB)",
            avg_block_size,
            avg_block_size as f64 / 1024.0
        );
    }
    println!("  Sizes:");
    println!(
        "    Uncompressed size: {} bytes ({:.1} MiB)",
        metadata.uncompressed_size,
        metadata.uncompressed_size as f64 / (1024.0 * 1024.0)
    );
    println!(
        "    Compressed size: {} bytes ({:.1} MiB)",
        metadata.compressed_size,
        metadata.compressed_size as f64 / (1024.0 * 1024.0)
    );
    if metadata.uncompressed_size > 0 {
        println!(
            "    Compression ratio: {:.2}%",
            (metadata.compressed_size as f64 / metadata.uncompressed_size as f64) * 100.0
        );
        if metadata.compressed_size <= metadata.uncompressed_size {
            println!(
                "    Space saved: {:.2}%",
                ((metadata.uncompressed_size - metadata.compressed_size) as f64
                    / metadata.uncompressed_size as f64)
                    * 100.0
            );
        } else {
            println!(
                "    Space overhead: {:.2}%",
                ((metadata.compressed_size - metadata.uncompressed_size) as f64
                    / metadata.uncompressed_size as f64)
                    * 100.0
            );
        }
    }
    println!("  Integrity:");
    println!("    Blake3 hash: {}", format_hex(&metadata.blake3_hash));
    println!("    RS parity: {}", format_hex(&metadata.rs_parity));
    println!("    Hash validated: {}", metadata.validated);
    println!("    Hash corrected: {}", metadata.corrected);

    Ok(())
}

fn format_prefilter(prefilter: &Prefilter) -> String {
    match prefilter {
        Prefilter::None => "None".to_string(),
        Prefilter::Delta { distance } => format!("Delta (distance: {})", distance),
        Prefilter::BcjX86 => "BCJ x86".to_string(),
        Prefilter::BcjArm => "BCJ ARM".to_string(),
        Prefilter::BcjArmThumb => "BCJ ARM Thumb".to_string(),
        Prefilter::BcjArm64 => "BCJ ARM64".to_string(),
        Prefilter::BcjSparc => "BCJ SPARC".to_string(),
        Prefilter::BcjPowerPc => "BCJ PowerPC".to_string(),
        Prefilter::BcjIa64 => "BCJ IA-64".to_string(),
        Prefilter::BcjRiscV => "BCJ RISC-V".to_string(),
    }
}

fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
