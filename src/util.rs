/// Format a size in bytes as a human-readable string with appropriate unit.
/// Uses binary units (KiB, MiB, GiB, etc.) and shows the highest unit above 1.
/// Examples: 1536 -> "1.5 KiB", 1048576 -> "1.0 MiB", 512 -> "512 B"
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    const THRESHOLD: f64 = 1024.0;

    if bytes == 0 {
        return "0 B".to_string();
    }

    let bytes_f = bytes as f64;
    let mut unit_index = 0;
    let mut size = bytes_f;

    // Find the appropriate unit (highest unit where size >= 1.0).
    while size >= THRESHOLD && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else if size >= 100.0 {
        format!("{:.0} {}", size, UNITS[unit_index])
    } else if size >= 10.0 {
        format!("{:.1} {}", size, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.00 KiB");
        assert_eq!(format_size(1536), "1.50 KiB");
        assert_eq!(format_size(10240), "10.0 KiB");
        assert_eq!(format_size(102400), "100 KiB");
        assert_eq!(format_size(1048576), "1.00 MiB");
        assert_eq!(format_size(1572864), "1.50 MiB");
        assert_eq!(format_size(1073741824), "1.00 GiB");
    }
}
