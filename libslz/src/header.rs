use super::{
    ByteWriter, Prefilter, SLZ_MAGIC, SLZ_VERSION, SLZOptions, Write, error_invalid_data,
    error_unsupported, lzma,
    reed_solomon::{code_34_10, code_64_40},
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SLZHeader {
    pub(crate) capabilities: u8,
    pub(crate) prefilter: Prefilter,
    pub(crate) block_size_exponent: u8,
    pub(crate) lc: u8,
    pub(crate) lp: u8,
    pub(crate) pb: u8,
    pub(crate) dict_size_log2: u8,
}

impl SLZHeader {
    pub(crate) fn from_options(options: &SLZOptions) -> Self {
        Self {
            capabilities: 0x00, // Currently set to 0x00 per specification
            prefilter: options.prefilter,
            block_size_exponent: options.block_size_exponent.unwrap_or(62),
            lc: options.lc,
            lp: options.lp,
            pb: options.pb,
            dict_size_log2: options.dictionary_size_log2,
        }
    }

    pub(crate) fn dict_size(&self) -> u32 {
        2u32.pow(self.dict_size_log2 as u32)
            .min(lzma::DICT_SIZE_MAX)
    }

    pub(crate) fn block_size(&self) -> u64 {
        2u64.pow(self.block_size_exponent as u32)
    }

    pub(crate) fn parse(buffer: &[u8; 34], apply_rs_correction: bool) -> crate::Result<SLZHeader> {
        let mut corrected_buffer = *buffer;

        if apply_rs_correction {
            let mut header_codeword = *buffer;

            let corrected = code_34_10::decode(&mut header_codeword)
                .map_err(|_| error_invalid_data("header Reed-Solomon correction failed"))?;

            if corrected {
                eprintln!("Header errors detected and corrected by Reed-Solomon");
                corrected_buffer = header_codeword;
            }
        }

        if corrected_buffer[0..4] != SLZ_MAGIC {
            return Err(error_invalid_data("invalid SLZ magic bytes"));
        }

        let version = corrected_buffer[4];
        if version != SLZ_VERSION {
            return Err(error_unsupported("unsupported SLZ version"));
        }

        let capabilities = corrected_buffer[5];
        if capabilities != 0x00 {
            return Err(error_unsupported("unsupported SLZ capabilities"));
        }

        let prefilter_byte = corrected_buffer[6];
        let prefilter = Prefilter::try_from(prefilter_byte)
            .map_err(|_| error_invalid_data("unsupported prefilter type"))?;

        let block_size_exponent = corrected_buffer[7];
        if !(16u8..=62u8).contains(&block_size_exponent) {
            return Err(error_invalid_data("invalid block size exponent"));
        }

        let lzma_props = u16::from_le_bytes([corrected_buffer[8], corrected_buffer[9]]);
        let props = (lzma_props & 0xFF) as u8;
        let lc = props % 9;
        let temp = props / 9;
        let lp = temp % 5;
        let pb = temp / 5;

        if lc > 8 || lp > 4 || pb > 4 {
            return Err(error_invalid_data("invalid LZMA properties"));
        }

        let dict_size_log2 = ((lzma_props >> 8) & 0xFF) as u8;
        if !(16u8..=31u8).contains(&dict_size_log2) {
            return Err(error_invalid_data("invalid dictionary size"));
        }

        Ok(SLZHeader {
            capabilities,
            prefilter,
            block_size_exponent,
            lc,
            lp,
            pb,
            dict_size_log2,
        })
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        let mut payload = [0u8; 10];

        payload[0..4].copy_from_slice(&SLZ_MAGIC);

        payload[4] = SLZ_VERSION;
        payload[5] = self.capabilities;

        payload[6] = u8::from(self.prefilter);
        payload[7] = self.block_size_exponent;

        let lzma_props_byte = (self.pb * 5 + self.lp) * 9 + self.lc;
        let lzma_props = u16::from_le_bytes([lzma_props_byte, self.dict_size_log2]);
        payload[8..10].copy_from_slice(&lzma_props.to_le_bytes());

        let parity = code_34_10::encode(&payload);

        writer.write_all(&payload)?;
        writer.write_all(&parity)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SLZBlockHeader {
    pub(crate) physical_size_with_flags: u64,
    pub(crate) blake3_hash: [u8; 32],
    pub(crate) rs_parity: [u8; 24],
}

impl SLZBlockHeader {
    /// Create a block header with appropriate MSB flags.
    pub(crate) fn new(physical_size: u64, is_partial: bool, blake3_hash: [u8; 32]) -> Self {
        // Clear top 2 bits
        let mut physical_size_with_flags = physical_size & !(0b11u64 << 62);

        if is_partial {
            // Set partial block flag
            physical_size_with_flags |= 1u64 << 62;
        }

        let mut payload = [0u8; 40];
        payload[..8].copy_from_slice(&physical_size_with_flags.to_le_bytes());
        payload[8..].copy_from_slice(&blake3_hash);
        let rs_parity = code_64_40::encode(&payload);
        Self {
            physical_size_with_flags,
            blake3_hash,
            rs_parity,
        }
    }

    pub(crate) fn parse(
        buffer: &[u8; 64],
        apply_rs_correction: bool,
    ) -> crate::Result<SLZBlockHeader> {
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

        let physical_size_with_flags = u64::from_le_bytes([
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

        Ok(SLZBlockHeader {
            physical_size_with_flags,
            blake3_hash,
            rs_parity,
        })
    }

    /// Get the physical block size without flag bits.
    pub(crate) fn physical_size(&self) -> u64 {
        self.physical_size_with_flags & !(0b11u64 << 62)
    }

    /// Check if this is a partial block (only allowed as the final block).
    pub(crate) fn is_partial_block(&self) -> bool {
        (self.physical_size_with_flags & (1u64 << 62)) != 0
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        writer.write_u64(self.physical_size_with_flags)?;
        writer.write_all(&self.blake3_hash)?;
        writer.write_all(&self.rs_parity)
    }
}
