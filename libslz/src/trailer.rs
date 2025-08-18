use super::{ByteWriter, Write, error_invalid_data, reed_solomon, reed_solomon::decode_64_40};

/// File trailer containing total uncompressed size, root hash, and Reed-Solomon parity.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SLZFileTrailer {
    /// Total uncompressed byte size for all blocks.
    pub(crate) total_uncompressed_size: u64,
    /// Blake3 root hash of the entire file.
    pub(crate) blake3_hash: [u8; 32],
    pub(crate) rs_parity: [u8; 24],
}

impl SLZFileTrailer {
    pub(crate) fn new(total_uncompressed_size: u64, blake3_hash: [u8; 32]) -> Self {
        let mut payload = [0u8; 40];
        payload[..8].copy_from_slice(&total_uncompressed_size.to_le_bytes());
        payload[8..].copy_from_slice(&blake3_hash);
        let rs_parity = reed_solomon::encode(&payload);
        Self {
            total_uncompressed_size,
            blake3_hash,
            rs_parity,
        }
    }

    pub(crate) fn parse(
        buffer: &[u8; 64],
        apply_rs_correction: bool,
    ) -> crate::Result<SLZFileTrailer> {
        let mut corrected_buffer = *buffer;

        if apply_rs_correction {
            let mut codeword = [0u8; 64];
            codeword.copy_from_slice(buffer);

            match decode_64_40(&mut codeword) {
                Ok(corrected) => {
                    if corrected {
                        eprintln!("final trailer errors detected and corrected by Reed-Solomon");
                        corrected_buffer.copy_from_slice(&codeword);
                    }
                }
                Err(_) => {
                    return Err(error_invalid_data(
                        "final trailer Reed-Solomon correction failed",
                    ));
                }
            }
        }

        let size_with_flag = u64::from_le_bytes([
            corrected_buffer[0],
            corrected_buffer[1],
            corrected_buffer[2],
            corrected_buffer[3],
            corrected_buffer[4],
            corrected_buffer[5],
            corrected_buffer[6],
            corrected_buffer[7],
        ]);

        // Strip MSB=1 flag to get actual uncompressed size
        let total_uncompressed_size = size_with_flag & !(1u64 << 63);

        let mut blake3_hash = [0u8; 32];
        blake3_hash.copy_from_slice(&corrected_buffer[8..40]);

        let mut rs_parity = [0u8; 24];
        rs_parity.copy_from_slice(&corrected_buffer[40..64]);

        Ok(SLZFileTrailer {
            total_uncompressed_size,
            blake3_hash,
            rs_parity,
        })
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        // Write size with MSB=1 to indicate final trailer
        let size_with_flag = self.total_uncompressed_size | (1u64 << 63);
        writer.write_u64(size_with_flag)?;
        writer.write_all(&self.blake3_hash)?;
        writer.write_all(&self.rs_parity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trailer_roundtrip() {
        let total_size = 1_000_000;
        let blake3_hash = [42u8; 32];

        let trailer = SLZFileTrailer::new(total_size, blake3_hash);

        let mut buffer = Vec::new();
        trailer.write(&mut buffer).unwrap();

        let mut buffer_array = [0u8; 64];
        buffer_array.copy_from_slice(&buffer);
        let parsed_trailer = SLZFileTrailer::parse(&buffer_array, true).unwrap();

        assert_eq!(parsed_trailer.total_uncompressed_size, total_size);
        assert_eq!(parsed_trailer.blake3_hash, blake3_hash);
    }

    #[test]
    fn test_trailer_zero_size() {
        let total_size = 0;
        let blake3_hash = [0u8; 32];

        let trailer = SLZFileTrailer::new(total_size, blake3_hash);

        let mut buffer = Vec::new();
        trailer.write(&mut buffer).unwrap();

        let mut buffer_array = [0u8; 64];
        buffer_array.copy_from_slice(&buffer);
        let parsed_trailer = SLZFileTrailer::parse(&buffer_array, true).unwrap();

        assert_eq!(parsed_trailer.total_uncompressed_size, 0);
        assert_eq!(parsed_trailer.blake3_hash, [0u8; 32]);
    }

    #[test]
    fn test_trailer_with_reed_solomon_correction() {
        let total_size = 1_000_000;
        let blake3_hash = [42u8; 32];

        let trailer = SLZFileTrailer::new(total_size, blake3_hash);

        let mut buffer = Vec::new();
        trailer.write(&mut buffer).unwrap();

        // Introduce a small error (within Reed-Solomon correction capability).
        buffer[10] ^= 0x01; // Flip a bit in the hash

        let mut buffer_array = [0u8; 64];
        buffer_array.copy_from_slice(&buffer);
        let parsed_trailer = SLZFileTrailer::parse(&buffer_array, true).unwrap();

        assert_eq!(parsed_trailer.total_uncompressed_size, total_size);
        assert_eq!(parsed_trailer.blake3_hash, blake3_hash);
    }

    #[test]
    fn test_trailer_reed_solomon_failure() {
        let total_size = 1_000_000;
        let blake3_hash = [42u8; 32];

        let trailer = SLZFileTrailer::new(total_size, blake3_hash);

        let mut buffer = Vec::new();
        trailer.write(&mut buffer).unwrap();

        // Introduce too many errors (beyond Reed-Solomon correction capability).
        for i in 0..20 {
            buffer[i] = 0xFF;
        }

        let mut buffer_array = [0u8; 64];
        buffer_array.copy_from_slice(&buffer);
        let result = SLZFileTrailer::parse(&buffer_array, true);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Reed-Solomon correction failed")
        );
    }
}
