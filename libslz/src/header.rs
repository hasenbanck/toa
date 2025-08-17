use super::{
    ByteReader, ByteWriter, Prefilter, Read, SLZ_MAGIC, SLZ_VERSION, SLZOptions, Write,
    error_invalid_data, error_unsupported, lzma,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SLZHeader {
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

    pub(crate) fn parse<R: Read>(mut reader: R) -> crate::Result<SLZHeader> {
        // Read and verify magic bytes.
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        if magic != SLZ_MAGIC {
            return Err(error_invalid_data("invalid SLZ magic bytes"));
        }

        // Read and verify version.
        let version = reader.read_u8()?;
        if version != SLZ_VERSION {
            return Err(error_unsupported("unsupported SLZ version"));
        }

        // Read prefilter
        let prefilter_byte = reader.read_u8()?;

        // Read block size exponent
        let block_size_exponent = reader.read_u8()?;
        if !(16u8..=62u8).contains(&block_size_exponent) {
            return Err(error_invalid_data("invalid block size exponent"));
        }

        // Read LZMA properties.
        let props = reader.read_u8()?;
        let lc = props % 9;
        let temp = props / 9;
        let lp = temp % 5;
        let pb = temp / 5;

        if lc > 8 || lp > 4 || pb > 4 {
            return Err(error_invalid_data("invalid LZMA properties"));
        }

        // Read dictionary size.
        let dict_size_log2 = reader.read_u8()?;
        if !(16u8..=31u8).contains(&dict_size_log2) {
            return Err(error_invalid_data("invalid dictionary size"));
        }

        // Read the optional prefilter configuration.
        let prefilter = match prefilter_byte {
            0x00 => Prefilter::None,
            0x01 => {
                // Delta filter - need to read distance.
                let distance_byte = reader.read_u8()?;
                Prefilter::Delta {
                    distance: (distance_byte as u16) + 1,
                }
            }
            0x02 => Prefilter::BcjX86,
            0x03 => Prefilter::BcjArm,
            0x04 => Prefilter::BcjArmThumb,
            0x05 => Prefilter::BcjArm64,
            0x06 => Prefilter::BcjSparc,
            0x07 => Prefilter::BcjPowerPc,
            0x08 => Prefilter::BcjIa64,
            0x09 => Prefilter::BcjRiscV,
            _ => return Err(error_invalid_data("unsupported prefilter type")),
        };

        Ok(SLZHeader {
            prefilter,
            block_size_exponent,
            lc,
            lp,
            pb,
            dict_size_log2,
        })
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        writer.write_all(&SLZ_MAGIC)?;

        writer.write_u8(SLZ_VERSION)?;

        let config = u8::from(self.prefilter);
        writer.write_u8(config)?;

        writer.write_u8(self.block_size_exponent)?;

        let lzma_props = (self.pb * 5 + self.lp) * 9 + self.lc;
        writer.write_u8(lzma_props)?;

        writer.write_u8(self.dict_size_log2)?;

        if let Prefilter::Delta { distance } = self.prefilter {
            writer.write_u8(distance as u8 - 1)?;
        }

        Ok(())
    }
}
