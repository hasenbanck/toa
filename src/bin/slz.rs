use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Read, Result, Write},
    num::NonZeroU32,
    process,
    time::Instant,
};

use clap::{Arg, ArgMatches, Command, value_parser};
use slz::{Prefilter, SLZOptions, SLZStreamingWriter};

struct Cli {
    input: String,
    output: Option<String>,
    preset: u32,
    block_size: Option<u32>,
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
            .about("Compress files using the SLZ (Streaming LZMA) format")
            .version(env!("CARGO_PKG_VERSION"))
            .arg(
                Arg::new("input")
                    .help("Input file to compress")
                    .value_name("FILE")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::new("output")
                    .help("Output file path (defaults to input + .slz extension)")
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
                    .help("Block size in bytes")
                    .long("block-size")
                    .value_name("bytes")
                    .value_parser(value_parser!(u32).range(1..=4294967295)),
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
                    .help("Dictionary size as power of 2 (16-32, e.g., 26 = 64MiB)")
                    .long("dict-size")
                    .value_name("N")
                    .value_parser(value_parser!(u8).range(16..=32)),
            )
    }

    fn from_matches(matches: &ArgMatches) -> Self {
        Self {
            input: matches.get_one::<String>("input").unwrap().clone(),
            output: matches.get_one::<String>("output").cloned(),
            preset: *matches.get_one::<u32>("preset").unwrap(),
            block_size: matches.get_one::<u32>("block-size").copied(),
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

fn main() {
    let matches = Cli::build_command().get_matches();
    let cli = Cli::from_matches(&matches);

    let output_filename = cli
        .output
        .clone()
        .unwrap_or_else(|| format!("{}.slz", cli.input));

    if let Err(error) = compress_file(&cli, &output_filename) {
        eprintln!("Error: {error}");
        process::exit(1);
    }

    println!("Compressed {} into {}", cli.input, output_filename);
}

fn compress_file(cli: &Cli, output_path: &str) -> Result<()> {
    let input_file = File::open(&cli.input)?;
    let file_size = input_file.metadata()?.len();
    let mut input_reader = BufReader::new(input_file);

    let output_file = File::create(output_path)?;
    let output_writer = BufWriter::new(output_file);

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
        options = options.with_block_size(NonZeroU32::new(block_size));
    }

    let mut slz_writer = SLZStreamingWriter::new(output_writer, options);

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
