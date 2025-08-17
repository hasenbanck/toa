mod compression;
mod decompression;
mod list;
mod util;

use std::{fs, io::Result, process};

use clap::{Arg, ArgMatches, Command, value_parser};
use libslz::Prefilter;

use crate::{
    compression::compress_file, decompression::decompress_file, list::list_file_info,
    util::format_size,
};

struct Cli {
    input: String,
    output: Option<String>,
    extract: bool,
    list: bool,
    keep: bool,
    verbose: bool,
    preset: u32,
    block_size: Option<u64>,
    block_count: Option<u64>,
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
            .arg_required_else_help(true)
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
                Arg::new("verbose")
                    .help("Show detailed output during operations")
                    .short('v')
                    .long("verbose")
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
                Arg::new("block-size")
                    .help("Block size in uncompressed bytes (must be multiple of 1024)")
                    .long("block-size")
                    .value_name("bytes")
                    .value_parser(value_parser!(u64).range(1024..=18446744073709551615))
                    .conflicts_with("block-count"),
            )
            .arg(
                Arg::new("block-count")
                    .help("Number of blocks to divide the file into (calculates block size automatically)")
                    .long("block-count")
                    .value_name("count")
                    .value_parser(value_parser!(u64).range(1..=18446744073709551615))
                    .conflicts_with("block-size"),
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
            .arg(
                Arg::new("preset")
                    .help("Compression preset level (0-9, higher is better compression)")
                    .short('p')
                    .long("preset")
                    .value_parser(value_parser!(u32).range(0..=9))
                    .default_value("6"),
            )
            .arg(
                Arg::new("0")
                    .help("Compression preset level 0 (fastest)")
                    .short('0')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "1", "2", "3", "4", "5", "6", "7", "8", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("1")
                    .help("Compression preset level 1")
                    .short('1')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "2", "3", "4", "5", "6", "7", "8", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("2")
                    .help("Compression preset level 2")
                    .short('2')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "3", "4", "5", "6", "7", "8", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("3")
                    .help("Compression preset level 3")
                    .short('3')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "4", "5", "6", "7", "8", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("4")
                    .help("Compression preset level 4")
                    .short('4')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "5", "6", "7", "8", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("5")
                    .help("Compression preset level 5")
                    .short('5')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "6", "7", "8", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("6")
                    .help("Compression preset level 6 (default)")
                    .short('6')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "7", "8", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("7")
                    .help("Compression preset level 7")
                    .short('7')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "6", "8", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("8")
                    .help("Compression preset level 8")
                    .short('8')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "6", "7", "9", "fastest", "best"]),
            )
            .arg(
                Arg::new("9")
                    .help("Compression preset level 9 (best compression)")
                    .short('9')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "6", "7", "8", "fastest", "best"]),
            )
            .arg(
                Arg::new("fastest")
                    .help("Fastest compression (same as -0)")
                    .long("fastest")
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "best"]),
            )
            .arg(
                Arg::new("best")
                    .help("Best compression (same as -9)")
                    .long("best")
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "fastest"]),
            )
    }

    fn from_matches(matches: &ArgMatches) -> Self {
        // Determine preset from shorthand flags or explicit preset.
        let preset = if matches.get_flag("0") || matches.get_flag("fastest") {
            0
        } else if matches.get_flag("1") {
            1
        } else if matches.get_flag("2") {
            2
        } else if matches.get_flag("3") {
            3
        } else if matches.get_flag("4") {
            4
        } else if matches.get_flag("5") {
            5
        } else if matches.get_flag("6") {
            6
        } else if matches.get_flag("7") {
            7
        } else if matches.get_flag("8") {
            8
        } else if matches.get_flag("9") || matches.get_flag("best") {
            9
        } else {
            *matches.get_one::<u32>("preset").unwrap()
        };

        // Validate block size alignment
        let block_size = matches.get_one::<u64>("block-size").copied();
        if let Some(size) = block_size {
            if size % 1024 != 0 {
                eprintln!("Error: Block size must be a multiple of 1024 bytes (1 KiB)");
                process::exit(1);
            }
        }

        Self {
            input: matches.get_one::<String>("input").unwrap().clone(),
            output: matches.get_one::<String>("output").cloned(),
            extract: matches.get_flag("extract"),
            list: matches.get_flag("list"),
            keep: matches.get_flag("keep"),
            verbose: matches.get_flag("verbose"),
            preset,
            block_size,
            block_count: matches.get_one::<u64>("block-count").copied(),
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
        // List mode - show metadata.
        if let Err(error) = list_file_info(&cli) {
            eprintln!("Error: Can't list file content: {error}");
            process::exit(1);
        }
    } else if cli.extract {
        // Extraction mode.
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
                    eprintln!("Error: Can't decompress file: {error}");
                    process::exit(1);
                }
            };

        if cli.verbose {
            let speed_mibs = if elapsed.as_secs_f64() > 0.0 {
                (uncompressed_size as f64) / (1024.0 * 1024.0 * elapsed.as_secs_f64())
            } else {
                0.0
            };

            println!("Compressed:   {}", format_size(compressed_size));
            println!("Uncompressed: {}", format_size(uncompressed_size));
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
        }

        if !cli.keep
            && let Err(error) = fs::remove_file(&cli.input)
        {
            eprintln!("Warning: Failed to remove input file: {error}");
        }
    } else {
        // Compression mode.
        let output_filename = cli
            .output
            .clone()
            .unwrap_or_else(|| format!("{}.slz", cli.input));

        let (uncompressed_size, compressed_size, elapsed) =
            match compress_file(&cli, &output_filename) {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("Error: Can't compress file: {error}");
                    process::exit(1);
                }
            };

        if cli.verbose {
            let speed_mibs = if elapsed.as_secs_f64() > 0.0 {
                (uncompressed_size as f64) / (1024.0 * 1024.0 * elapsed.as_secs_f64())
            } else {
                0.0
            };

            println!("Compressed:   {}", format_size(compressed_size));
            println!("Uncompressed: {}", format_size(uncompressed_size));
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
        }

        if !cli.keep
            && let Err(error) = fs::remove_file(&cli.input)
        {
            eprintln!("Warning: Failed to remove input file: {error}");
        }
    }

    Ok(())
}
