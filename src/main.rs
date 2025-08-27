mod compression;
mod decompression;
mod list;
mod util;

use std::{fs, io::Result, path::PathBuf, process};

use clap::{Arg, ArgMatches, Command, value_parser};
use glob::glob;
use libtoa::{ErrorCorrection, Prefilter};

use crate::{
    compression::compress_file,
    decompression::{decompress_file, test_file},
    list::list_file_info,
    util::format_size,
};

struct Cli {
    inputs: Vec<PathBuf>,
    output: Option<String>,
    extract: bool,
    list: bool,
    test: bool,
    keep: bool,
    verify: bool,
    verbose: bool,
    preset: u32,
    block_size: Option<u8>,
    block_count: Option<u64>,
    threads: usize,
    x86: bool,
    arm: bool,
    armthumb: bool,
    arm64: bool,
    sparc: bool,
    powerpc: bool,
    ia64: bool,
    riscv: bool,
    lc: Option<u8>,
    lp: Option<u8>,
    pb: Option<u8>,
    dict_size: Option<u8>,
    ecc: ErrorCorrection,
}

impl Cli {
    fn build_command() -> Command {
        Command::new("toa")
            .about("Compress and decompress files using the TOA compression file format")
            .long_about("TOA compression format optimized for streaming, parallelization, and error correction.\n\nUSAGE RECOMMENDATIONS:\n• Use preset 6 (default)\n• Files >1 GiB: Use presets 7-9 for maximum compression\n• Block size automatically matches dictionary size for optimal performance")
            .version(env!("CARGO_PKG_VERSION"))
            .arg_required_else_help(true)
            .arg(
                Arg::new("input")
                    .help("Input file(s) to compress or decompress (supports wildcards)")
                    .value_name("FILE")
                    .required(true)
                    .num_args(1..)
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
                    .help("List information about the TOA file")
                    .short('l')
                    .long("list")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("test")
                    .help("Test decompression without storing output")
                    .long("test")
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
                Arg::new("verify")
                    .help("Test decompression after compression to ensure data integrity (original file only deleted if verification passes)")
                    .long("verify")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("output")
                    .help("Output file path (defaults to input + .toa for compression, or input without .toa for extraction)")
                    .short('o')
                    .long("output")
                    .value_name("FILE"),
            )
            .arg(
                Arg::new("block-size")
                    .help("Block size as power of 2 (0, 16-62, e.g., 26 = 64 MiB). Use 0 for maximum block size. Default: matches dictionary size of selected preset. For files >256 MiB, block size is automatically increased by 1 for better compression.")
                    .long("block-size")
                    .value_name("N")
                    .value_parser(value_parser!(u8).range(0..=62)),
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
                Arg::new("threads")
                    .help("Number of threads to use for multithreaded compression / decompression (0 = automatic, defaults to number of CPU cores). Higher thread counts benefit from smaller block sizes for better parallelization.")
                    .short('t')
                    .long("threads")
                    .value_name("N")
                    .value_parser(value_parser!(usize))
                    .default_value("0"),
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
                    .help("Dictionary size as power of 2 (16-30, e.g., 26 = 64 MiB)")
                    .long("dict-size")
                    .value_name("N")
                    .value_parser(value_parser!(u8).range(16..=30)),
            )
            .arg(
                Arg::new("ecc")
                    .help("Error correction level for data protection. Use Standard unless you have a specific reason not to. It handles all normal storage degradation for decades. Paranoid and Extreme are for specialized scenarios like single-copy archives on sketchy media or century-scale preservation.")
                    .long("ecc")
                    .value_name("LEVEL")
                    .value_parser(["none", "standard", "paranoid", "extreme"])
                    .default_value("standard"),
            )
            .arg(
                Arg::new("preset")
                    .help("Compression preset level (0-9, higher is better compression). Recommended: In general 6. Higher for files larger than 128 MiB.")
                    .short('p')
                    .long("preset")
                    .value_parser(value_parser!(u32).range(0..=9))
                    .default_value("6"),
            )
            .arg(
                Arg::new("0")
                    .help("Compression preset level 0 (ultra-fast, lowest compression)")
                    .short('0')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "1", "2", "3", "4", "5", "6", "7", "8", "9"]),
            )
            .arg(
                Arg::new("1")
                    .help("Compression preset level 1")
                    .short('1')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "2", "3", "4", "5", "6", "7", "8", "9"]),
            )
            .arg(
                Arg::new("2")
                    .help("Compression preset level 2")
                    .short('2')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "3", "4", "5", "6", "7", "8", "9"]),
            )
            .arg(
                Arg::new("3")
                    .help("Compression preset level 3")
                    .short('3')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "4", "5", "6", "7", "8", "9"]),
            )
            .arg(
                Arg::new("4")
                    .help("Compression preset level 4")
                    .short('4')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "5", "6", "7", "8", "9"]),
            )
            .arg(
                Arg::new("5")
                    .help("Compression preset level 5")
                    .short('5')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "6", "7", "8", "9"]),
            )
            .arg(
                Arg::new("6")
                    .help("Compression preset level 6 (default, maximum compression)")
                    .short('6')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "7", "8", "9"]),
            )
            .arg(
                Arg::new("7")
                    .help("Compression preset level 7 (for files larger than 128 MiB)")
                    .short('7')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "6", "8", "9"]),
            )
            .arg(
                Arg::new("8")
                    .help("Compression preset level 8 (for files larger than 256 MiB)")
                    .short('8')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "6", "7", "9"]),
            )
            .arg(
                Arg::new("9")
                    .help("Compression preset level 9 (for files larger than 512 MiB)")
                    .short('9')
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(["preset", "0", "1", "2", "3", "4", "5", "6", "7", "8"]),
            )
    }

    fn from_matches(matches: &ArgMatches) -> Self {
        // Determine preset from shorthand flags or explicit preset.
        let preset = if matches.get_flag("0") {
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
        } else if matches.get_flag("9") {
            9
        } else {
            *matches.get_one::<u32>("preset").unwrap()
        };

        // Handle thread count - 0 means automatic
        let threads = match *matches.get_one::<usize>("threads").unwrap() {
            0 => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            n => n,
        };

        let input_patterns: Vec<String> = matches
            .get_many::<String>("input")
            .unwrap()
            .cloned()
            .collect();

        let mut inputs = Vec::new();
        for pattern in input_patterns {
            if pattern.contains('*') {
                match glob(&pattern) {
                    Ok(paths) => {
                        for entry in paths {
                            match entry {
                                Ok(path) => inputs.push(path),
                                Err(error) => {
                                    eprintln!(
                                        "Warning: Error reading path in pattern '{pattern}': {error}",
                                    );
                                }
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("Error: Invalid pattern '{pattern}': {error}");
                        process::exit(1);
                    }
                }
            } else {
                inputs.push(PathBuf::from(pattern));
            }
        }

        if inputs.is_empty() {
            eprintln!("Error: No files found matching the specified pattern(s)");
            process::exit(1);
        }

        Self {
            inputs,
            output: matches.get_one::<String>("output").cloned(),
            extract: matches.get_flag("extract"),
            list: matches.get_flag("list"),
            test: matches.get_flag("test"),
            keep: matches.get_flag("keep"),
            verify: matches.get_flag("verify"),
            verbose: matches.get_flag("verbose"),
            preset,
            block_size: matches.get_one::<u8>("block-size").copied(),
            block_count: matches.get_one::<u64>("block-count").copied(),
            threads,
            x86: matches.get_flag("x86"),
            arm: matches.get_flag("arm"),
            armthumb: matches.get_flag("armthumb"),
            arm64: matches.get_flag("arm64"),
            sparc: matches.get_flag("sparc"),
            powerpc: matches.get_flag("powerpc"),
            ia64: matches.get_flag("ia64"),
            riscv: matches.get_flag("riscv"),
            lc: matches.get_one::<u8>("lc").copied(),
            lp: matches.get_one::<u8>("lp").copied(),
            pb: matches.get_one::<u8>("pb").copied(),
            dict_size: matches.get_one::<u8>("dict-size").copied(),
            ecc: match matches.get_one::<String>("ecc").unwrap().as_str() {
                "none" => ErrorCorrection::None,
                "standard" => ErrorCorrection::Standard,
                "paranoid" => ErrorCorrection::Paranoid,
                "extreme" => ErrorCorrection::Extreme,
                _ => ErrorCorrection::Standard,
            },
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
            None => Prefilter::None,
            _ => unreachable!(),
        })
    }
}

fn main() -> Result<()> {
    let matches = Cli::build_command().get_matches();
    let cli = Cli::from_matches(&matches);

    // Check for output argument conflicts with multiple files.
    if cli.inputs.len() > 1 && cli.output.is_some() {
        eprintln!("Error: --output cannot be used with multiple input files");
        process::exit(1);
    }

    for input_path in cli.inputs.clone() {
        let input_str = input_path.to_string_lossy().to_string();

        if cli.inputs.len() > 1 && cli.verbose {
            println!("Processing: {}", input_str);
        }

        if cli.list {
            // List mode - show metadata.
            if let Err(error) = list_file_info(&input_str) {
                eprintln!("Error: Can't list file content for '{input_str}': {error}");
                process::exit(1);
            }
            if cli.inputs.len() > 1 {
                println!();
            }
        } else if cli.test {
            // Test mode - decompress without storing output.
            let (compressed_size, uncompressed_size, elapsed) =
                match test_file(&input_str, cli.threads) {
                    Ok(result) => result,
                    Err(error) => {
                        eprintln!("Error: Can't test file '{input_str}': {error}");
                        process::exit(1);
                    }
                };

            if cli.verbose {
                let speed_mibs = if elapsed.as_secs_f64() > 0.0 {
                    (uncompressed_size as f64) / (1024.0 * 1024.0 * elapsed.as_secs_f64())
                } else {
                    0.0
                };

                if cli.inputs.len() > 1 {
                    println!("File: {input_str}");
                }
                println!("Compressed:   {}", format_size(compressed_size));
                println!("Uncompressed: {}", format_size(uncompressed_size));
                println!(
                    "Compression ratio: {:.2}%",
                    if uncompressed_size > 0 {
                        (compressed_size as f64 / uncompressed_size as f64) * 100.0
                    } else {
                        0.0
                    },
                );
                println!("Test time: {:.3}s", elapsed.as_secs_f64(),);
                println!("Test speed: {speed_mibs:.1} MiB/s");
                if cli.inputs.len() > 1 {
                    println!();
                }
            }

            if cli.inputs.len() == 1 {
                println!("Test completed successfully");
            } else {
                println!("Test completed successfully for '{}'", input_str);
            }
        } else if cli.extract {
            // Extraction mode.
            let output_filename = cli.output.clone().unwrap_or_else(|| {
                if input_str.ends_with(".toa") {
                    input_str[..input_str.len() - 4].to_string()
                } else {
                    format!("{input_str}.extracted")
                }
            });

            let (compressed_size, uncompressed_size, elapsed) =
                match decompress_file(&input_str, &output_filename, cli.threads) {
                    Ok(result) => result,
                    Err(error) => {
                        eprintln!("Error: Can't decompress file '{input_str}': {error}");
                        process::exit(1);
                    }
                };

            if cli.verbose {
                let speed_mibs = if elapsed.as_secs_f64() > 0.0 {
                    (uncompressed_size as f64) / (1024.0 * 1024.0 * elapsed.as_secs_f64())
                } else {
                    0.0
                };

                if cli.inputs.len() > 1 {
                    println!("File: {input_str}");
                }
                println!("Compressed:   {}", format_size(compressed_size));
                println!("Uncompressed: {}", format_size(uncompressed_size));
                println!(
                    "Compression ratio: {:.2}%",
                    if uncompressed_size > 0 {
                        (compressed_size as f64 / uncompressed_size as f64) * 100.0
                    } else {
                        0.0
                    },
                );
                println!("Decompression time: {:.3}s", elapsed.as_secs_f64(),);
                println!("Decompression speed: {speed_mibs:.1} MiB/s");
                if cli.inputs.len() > 1 {
                    println!();
                }
            }

            if !cli.keep
                && let Err(error) = fs::remove_file(&input_str)
            {
                eprintln!("Warning: Failed to remove input file '{input_str}': {error}");
            }
        } else {
            // Compression mode.
            let output_filename = cli
                .output
                .clone()
                .unwrap_or_else(|| format!("{input_str}.toa"));

            let (uncompressed_size, compressed_size, elapsed) =
                match compress_file(&cli, input_path.as_path(), &output_filename) {
                    Ok(result) => result,
                    Err(error) => {
                        eprintln!("Error: Can't compress file '{input_str}': {error}");
                        process::exit(1);
                    }
                };

            if cli.verify {
                if cli.verbose {
                    println!("Verifying compressed file...");
                }

                if let Err(error) = test_file(&output_filename, cli.threads) {
                    eprintln!(
                        "Error: Verification failed - compressed file '{output_filename}' is corrupt: {error}"
                    );
                    if let Err(remove_error) = fs::remove_file(&output_filename) {
                        eprintln!(
                            "Warning: Failed to remove corrupt compressed file '{output_filename}': {remove_error}"
                        );
                    }
                    process::exit(1);
                }

                if cli.verbose {
                    println!("Verification successful");
                }
            }

            if cli.verbose {
                let speed_mibs = if elapsed.as_secs_f64() > 0.0 {
                    (uncompressed_size as f64) / (1024.0 * 1024.0 * elapsed.as_secs_f64())
                } else {
                    0.0
                };

                if cli.inputs.len() > 1 {
                    println!("File: {input_str}");
                }
                println!("Compressed:   {}", format_size(compressed_size));
                println!("Uncompressed: {}", format_size(uncompressed_size));
                println!(
                    "Compression ratio: {:.2}%",
                    if uncompressed_size > 0 {
                        (compressed_size as f64 / uncompressed_size as f64) * 100.0
                    } else {
                        0.0
                    },
                );
                println!("Compression time: {:.3}s", elapsed.as_secs_f64(),);
                println!("Compression speed: {speed_mibs:.1} MiB/s");
                if cli.inputs.len() > 1 {
                    println!();
                }
            }

            if !cli.keep
                && let Err(error) = fs::remove_file(&input_str)
            {
                eprintln!("Warning: Failed to remove input file '{input_str}': {error}");
            }
        }
    }

    Ok(())
}
