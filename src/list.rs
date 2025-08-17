use std::fs::File;

use libslz::{Prefilter, SLZMetadata};

use crate::Cli;

pub(crate) fn list_file_info(cli: &Cli) -> std::io::Result<()> {
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
