use std::process;

pub fn test_simd_features() {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unsupported architecture"
    };

    println!("Architecture: {arch}\n");
    println!("{:<18} {:<14}", "Instruction Set", "Status");
    println!("{:<18} {:<14}", "---------------", "----------");

    #[cfg(target_arch = "x86_64")]
    test_x86_64_features();
    #[cfg(target_arch = "aarch64")]
    test_aarch64_features();

    process::exit(0);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn print_feature_status(name: &str, supported: bool) {
    println!(
        "{:<18} {:<14}",
        name,
        if supported {
            "Supported"
        } else {
            "Not Supported"
        }
    );
}

#[cfg(target_arch = "x86_64")]
fn test_x86_64_features() {
    print_feature_status("SSE2", is_x86_feature_detected!("sse2"));
    print_feature_status("SSSE3", is_x86_feature_detected!("ssse3"));
    print_feature_status("AVX2", is_x86_feature_detected!("avx2"));
    print_feature_status("GFNI", is_x86_feature_detected!("gfni"));
}

#[cfg(target_arch = "aarch64")]
fn test_aarch64_features() {
    print_feature_status("NEON", std::arch::is_aarch64_feature_detected!("neon"));
}
