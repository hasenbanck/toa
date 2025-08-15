use super::{
    ByteReader, ByteWriter, Read, Write, error_invalid_data, reed_solomon, reed_solomon::decode,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SLZTrailer {
    pub(crate) uncompressed_size: u64,
    pub(crate) blake3_hash: [u8; 32],
    pub(crate) rs_parity: [u8; 32],
}

impl SLZTrailer {
    pub(crate) fn new(uncompressed_size: u64, blake3_hash: [u8; 32]) -> Self {
        let rs_parity = reed_solomon::encode(&blake3_hash);
        Self {
            uncompressed_size,
            blake3_hash,
            rs_parity,
        }
    }

    pub(crate) fn parse<R: Read>(mut reader: R) -> crate::Result<SLZTrailer> {
        let uncompressed_size = reader.read_u64()?;

        let mut blake3_hash = [0u8; 32];
        reader.read_exact(&mut blake3_hash)?;

        let mut rs_parity = [0u8; 32];
        reader.read_exact(&mut rs_parity)?;

        Ok(SLZTrailer {
            uncompressed_size,
            blake3_hash,
            rs_parity,
        })
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        // Write end-of-blocks marker.
        writer.write_u64(0)?;

        // Write uncompressed size field.
        writer.write_u64(self.uncompressed_size)?;

        // Write Blake3 hash.
        writer.write_all(&self.blake3_hash)?;

        // Write Reed-Solomon parity.
        writer.write_all(&self.rs_parity)?;

        Ok(())
    }

    pub(crate) fn verify(
        &self,
        validate_trailer: bool,
        computed_bytes: &[u8; 32],
    ) -> crate::Result<()> {
        if !validate_trailer {
            return match computed_bytes == &self.blake3_hash {
                true => Ok(()),
                false => Err(error_invalid_data("Blake3 hash mismatch")),
            };
        }

        let mut codeword = [0u8; 64];
        codeword[..32].copy_from_slice(&self.blake3_hash);
        codeword[32..].copy_from_slice(&self.rs_parity);

        match decode(&mut codeword) {
            Ok(corrected) => {
                if corrected {
                    eprintln!("blake3 hash was corrected by the error correction");
                }

                let corrected_hash = &codeword[..32];
                if computed_bytes == corrected_hash {
                    Ok(())
                } else {
                    Err(error_invalid_data("blake3 hash mismatch"))
                }
            }
            Err(_) => Err(error_invalid_data(
                "blake3 hash is corrupted and can't be corrected",
            )),
        }
    }
}
