use super::{
    ByteReader, ByteWriter, Prefilter, Read, SLZ_MAGIC, SLZ_VERSION, SLZOptions, Write,
    error_invalid_data, error_unsupported, lzma,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SLZHeader {
    pub(crate) prefilter: Prefilter,
    pub(crate) lc: u8,
    pub(crate) lp: u8,
    pub(crate) pb: u8,
    pub(crate) dict_size_log2: u8,
}

impl SLZHeader {
    pub(crate) fn from_options(options: &SLZOptions) -> Self {
        Self {
            prefilter: options.prefilter,
            lc: options.lc,
            lp: options.lp,
            pb: options.pb,
            dict_size_log2: options.dictionary_size_log2,
        }
    }

    pub(crate) fn dict_size(&self) -> u32 {
        2u32.pow((self.dict_size_log2) as u32)
            .min(lzma::DICT_SIZE_MAX)
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

        // Read prefilter configuration.
        let prefilter_byte = reader.read_u8()?;
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
        let dict_size_log2 = reader.read_u8()? + 16;
        if dict_size_log2 > 31 {
            return Err(error_invalid_data("invalid dictionary size"));
        }

        Ok(SLZHeader {
            prefilter,
            lc,
            lp,
            pb,
            dict_size_log2,
        })
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        // Magic bytes
        writer.write_all(&SLZ_MAGIC)?;

        // Version
        writer.write_u8(SLZ_VERSION)?;

        // Prefilter configuration byte.
        let config = u8::from(self.prefilter);
        writer.write_u8(config)?;

        // Prefilter properties
        if let Prefilter::Delta { distance } = self.prefilter {
            writer.write_u8(distance as u8 - 1)?;
        }

        // LZMA properties byte: (pb * 5 + lp) * 9 + lc
        let props = (self.pb * 5 + self.lp) * 9 + self.lc;
        writer.write_u8(props)?;

        // Dictionary size: log2 minus 16
        writer.write_u8(self.dict_size_log2 - 16)?;

        Ok(())
    }
}
