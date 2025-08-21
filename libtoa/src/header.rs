use super::{
    ErrorCorrection, Prefilter, TOA_MAGIC, TOA_VERSION, TOAOptions, Write, error_invalid_data,
    error_unsupported, lzma,
    reed_solomon::{code_32_10, code_64_40},
};

/// TOA file header containing format metadata and compression parameters.
#[derive(Debug, Clone, Copy)]
pub struct TOAHeader {
    capabilities: u8,
    prefilter: Prefilter,
    block_size_exponent: u8,
    lc: u8,
    lp: u8,
    pb: u8,
    dict_size_log2: u8,
}

impl TOAHeader {
    /// Create a new TOA header from options.
    pub fn from_options(options: &TOAOptions) -> Self {
        Self {
            capabilities: options.error_correction.capability_bits(),
            prefilter: options.prefilter,
            block_size_exponent: options.block_size_exponent.unwrap_or(62),
            lc: options.lc,
            lp: options.lp,
            pb: options.pb,
            dict_size_log2: options.dictionary_size_log2,
        }
    }

    /// Get the capabilities field.
    pub fn capabilities(&self) -> u8 {
        self.capabilities
    }

    /// Get the error correction level from the capabilities.
    pub fn error_correction(&self) -> ErrorCorrection {
        match self.capabilities & 0b11 {
            0b00 => ErrorCorrection::None,
            0b01 => ErrorCorrection::Light,
            0b10 => ErrorCorrection::Medium,
            0b11 => ErrorCorrection::Heavy,
            _ => unreachable!(),
        }
    }

    /// Get the prefilter used.
    pub fn prefilter(&self) -> Prefilter {
        self.prefilter
    }

    /// Get the LZMA literal context bits.
    pub fn lc(&self) -> u8 {
        self.lc
    }

    /// Get the LZMA literal position bits.
    pub fn lp(&self) -> u8 {
        self.lp
    }

    /// Get the LZMA position bits.
    pub fn pb(&self) -> u8 {
        self.pb
    }

    /// Get the actual dictionary size.
    pub fn dict_size(&self) -> u32 {
        2u32.pow(self.dict_size_log2 as u32)
            .min(lzma::DICT_SIZE_MAX)
    }

    /// Get the actual block size.
    pub fn block_size(&self) -> u64 {
        2u64.pow(self.block_size_exponent as u32)
    }

    /// Parse an TOA header from a buffer.
    pub fn parse(buffer: &[u8; 32], apply_rs_correction: bool) -> crate::Result<TOAHeader> {
        let mut corrected_buffer = *buffer;

        if apply_rs_correction {
            let mut header_codeword = *buffer;

            let corrected = code_32_10::decode(&mut header_codeword)
                .map_err(|_| error_invalid_data("header Reed-Solomon correction failed"))?;

            if corrected {
                eprintln!("Header errors detected and corrected by Reed-Solomon");
                corrected_buffer = header_codeword;
            }
        }

        if corrected_buffer[0..4] != TOA_MAGIC {
            return Err(error_invalid_data("invalid TOA magic bytes"));
        }

        let version = corrected_buffer[4];
        if version != TOA_VERSION {
            return Err(error_unsupported("unsupported TOA version"));
        }

        let capabilities = corrected_buffer[5];
        if (capabilities & 0b11111100) != 0 {
            return Err(error_unsupported(
                "unsupported TOA capabilities (reserved bits set)",
            ));
        }

        let error_correction_bits = capabilities & 0b11;
        if error_correction_bits > 0b11 {
            return Err(error_unsupported("invalid error correction level"));
        }

        let prefilter_byte = corrected_buffer[6];
        let prefilter = Prefilter::try_from(prefilter_byte)
            .map_err(|_| error_invalid_data("unsupported prefilter type"))?;

        let block_size_exponent = corrected_buffer[7];
        if !(16u8..=62u8).contains(&block_size_exponent) {
            return Err(error_invalid_data("invalid block size exponent"));
        }

        let lzma_props_byte = corrected_buffer[8];
        let dict_size_log2 = corrected_buffer[9];

        let lc = lzma_props_byte % 9;
        let temp = lzma_props_byte / 9;
        let lp = temp % 5;
        let pb = temp / 5;

        if lc > 8 || lp > 4 || pb > 4 {
            return Err(error_invalid_data("invalid LZMA properties"));
        }
        if !(16u8..=31u8).contains(&dict_size_log2) {
            return Err(error_invalid_data("invalid dictionary size"));
        }

        Ok(TOAHeader {
            capabilities,
            prefilter,
            block_size_exponent,
            lc,
            lp,
            pb,
            dict_size_log2,
        })
    }

    /// Write the header to a writer.
    pub fn write<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        let mut data_bytes = [0u8; 10];

        data_bytes[0..4].copy_from_slice(&TOA_MAGIC);
        data_bytes[4] = TOA_VERSION;
        data_bytes[5] = self.capabilities;
        data_bytes[6] = u8::from(self.prefilter);
        data_bytes[7] = self.block_size_exponent;

        let lzma_props_byte = (self.pb * 5 + self.lp) * 9 + self.lc;
        data_bytes[8] = lzma_props_byte;
        data_bytes[9] = self.dict_size_log2;

        let parity_bytes = code_32_10::encode(&data_bytes);
        let mut header_bytes = [0; 32];
        header_bytes[..10].copy_from_slice(&data_bytes);
        header_bytes[10..].copy_from_slice(&parity_bytes);

        writer.write_all(&header_bytes)
    }
}

/// TOA block header containing size information, hash, and Reed-Solomon parity.
#[derive(Debug, Clone, Copy)]
pub struct TOABlockHeader {
    physical_size_with_flags: u64,
    blake3_hash: [u8; 32],
    rs_parity: [u8; 24],
}

impl TOABlockHeader {
    /// Create a block header with appropriate MSB flags.
    pub fn new(physical_size: u64, is_partial: bool, blake3_hash: [u8; 32]) -> Self {
        // Clear top 2 bits
        let mut physical_size_with_flags = physical_size & !(0b11u64 << 62);

        if is_partial {
            // Set partial block flag
            physical_size_with_flags |= 1u64 << 62;
        }

        let mut payload = [0u8; 40];
        payload[..8].copy_from_slice(&physical_size_with_flags.to_be_bytes());
        payload[8..].copy_from_slice(&blake3_hash);

        let rs_parity = code_64_40::encode(&payload);

        Self {
            physical_size_with_flags,
            blake3_hash,
            rs_parity,
        }
    }

    /// Parse a block header from a buffer.
    pub fn parse(buffer: &[u8; 64], apply_rs_correction: bool) -> crate::Result<TOABlockHeader> {
        let mut corrected_buffer = *buffer;

        if apply_rs_correction {
            let mut codeword = [0u8; 64];
            codeword.copy_from_slice(buffer);

            match code_64_40::decode(&mut codeword) {
                Ok(corrected) => {
                    if corrected {
                        eprintln!("block header errors detected and corrected by Reed-Solomon");
                        corrected_buffer.copy_from_slice(&codeword);
                    }
                }
                Err(_) => {
                    return Err(error_invalid_data(
                        "block header Reed-Solomon correction failed",
                    ));
                }
            }
        }

        let physical_size_with_flags = u64::from_be_bytes([
            corrected_buffer[0],
            corrected_buffer[1],
            corrected_buffer[2],
            corrected_buffer[3],
            corrected_buffer[4],
            corrected_buffer[5],
            corrected_buffer[6],
            corrected_buffer[7],
        ]);

        let mut blake3_hash = [0u8; 32];
        blake3_hash.copy_from_slice(&corrected_buffer[8..40]);

        let mut rs_parity = [0u8; 24];
        rs_parity.copy_from_slice(&corrected_buffer[40..64]);

        Ok(TOABlockHeader {
            physical_size_with_flags,
            blake3_hash,
            rs_parity,
        })
    }

    /// Get the Blake3 hash.
    pub fn blake3_hash(&self) -> [u8; 32] {
        self.blake3_hash
    }

    /// Get the Reed-Solomon parity data.
    pub fn rs_parity(&self) -> [u8; 24] {
        self.rs_parity
    }

    /// Get the physical block size without flag bits.
    pub fn physical_size(&self) -> u64 {
        self.physical_size_with_flags & !(0b11u64 << 62)
    }

    /// Check if this is a partial block (only allowed as the final block).
    pub fn is_partial_block(&self) -> bool {
        (self.physical_size_with_flags & (1u64 << 62)) != 0
    }

    /// Write the block header to a writer.
    pub fn write<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        let mut header_bytes = [0u8; 64];
        header_bytes[0..8].copy_from_slice(&self.physical_size_with_flags.to_be_bytes());
        header_bytes[8..40].copy_from_slice(&self.blake3_hash);
        header_bytes[40..64].copy_from_slice(&self.rs_parity);

        writer.write_all(&header_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toa_header_roundtrip() {
        let options = TOAOptions::from_preset(5)
            .with_prefilter(Prefilter::BcjX86)
            .with_block_size_exponent(Some(20));

        let header = TOAHeader::from_options(&options);

        let mut buffer = Vec::new();
        header.write(&mut buffer).unwrap();

        let mut header_array = [0u8; 32];
        header_array.copy_from_slice(&buffer);
        let parsed_header = TOAHeader::parse(&header_array, true).unwrap();

        assert_eq!(parsed_header.capabilities(), header.capabilities());
        assert_eq!(parsed_header.prefilter(), header.prefilter());
        assert_eq!(parsed_header.lc(), header.lc());
        assert_eq!(parsed_header.lp(), header.lp());
        assert_eq!(parsed_header.pb(), header.pb());
        assert_eq!(parsed_header.dict_size(), header.dict_size());
        assert_eq!(parsed_header.block_size(), header.block_size());
    }

    #[test]
    fn test_toa_block_header_roundtrip() {
        let physical_size = 65536;
        let is_partial = false;
        let blake3_hash = [42u8; 32];

        let block_header = TOABlockHeader::new(physical_size, is_partial, blake3_hash);

        let mut buffer = Vec::new();
        block_header.write(&mut buffer).unwrap();

        let mut header_array = [0u8; 64];
        header_array.copy_from_slice(&buffer);
        let parsed_header = TOABlockHeader::parse(&header_array, true).unwrap();

        assert_eq!(parsed_header.physical_size(), physical_size);
        assert_eq!(parsed_header.is_partial_block(), is_partial);
        assert_eq!(parsed_header.blake3_hash(), blake3_hash);
        assert_eq!(parsed_header.rs_parity(), block_header.rs_parity());
    }
}
