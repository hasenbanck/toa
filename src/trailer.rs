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
        let mut bytes_read = 0;

        // Try to read the full parity data.
        while bytes_read < 32 {
            match reader.read(&mut rs_parity[bytes_read..]) {
                Ok(0) => {
                    // EOF reached - attempt recovery with partial data.
                    return Self::parse_truncated_trailer(
                        uncompressed_size,
                        blake3_hash,
                        rs_parity,
                        bytes_read,
                    );
                }
                Ok(read) => {
                    bytes_read += read;
                }
                Err(error) => {
                    #[cfg(feature = "std")]
                    {
                        if error.kind() == std::io::ErrorKind::UnexpectedEof {
                            // Attempt recovery with partial data
                            return Self::parse_truncated_trailer(
                                uncompressed_size,
                                blake3_hash,
                                rs_parity,
                                bytes_read,
                            );
                        }
                    }
                    return Err(error);
                }
            }
        }

        // Complete trailer read successfully.
        Ok(SLZTrailer {
            uncompressed_size,
            blake3_hash,
            rs_parity,
        })
    }

    fn parse_truncated_trailer(
        uncompressed_size: u64,
        blake3_hash: [u8; 32],
        partial_rs_parity: [u8; 32],
        bytes_read: usize,
    ) -> crate::Result<SLZTrailer> {
        eprintln!(
            "Warning: Truncated trailer detected. Missing {} bytes from Reed-Solomon parity. Attempting recovery...",
            32 - bytes_read
        );

        let mut codeword = [0u8; 64];
        codeword[..32].copy_from_slice(&blake3_hash);
        codeword[32..32 + bytes_read].copy_from_slice(&partial_rs_parity[..bytes_read]);

        // Attempt Reed-Solomon recovery.
        match decode(&mut codeword) {
            Ok(corrected) => {
                if corrected || bytes_read < 32 {
                    if bytes_read < 32 {
                        eprintln!(
                            "Reed-Solomon successfully recovered truncated trailer (missing {} bytes)",
                            32 - bytes_read
                        );
                    } else {
                        eprintln!("Reed-Solomon corrected errors in trailer");
                    }
                }

                let recovered_blake3_hash = {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&codeword[..32]);
                    hash
                };

                let recovered_rs_parity = {
                    let mut parity = [0u8; 32];
                    parity.copy_from_slice(&codeword[32..]);
                    parity
                };

                Ok(SLZTrailer {
                    uncompressed_size,
                    blake3_hash: recovered_blake3_hash,
                    rs_parity: recovered_rs_parity,
                })
            }
            Err(_) => {
                if bytes_read < 32 {
                    Err(error_invalid_data(
                        "trailer is truncated and Reed-Solomon recovery failed",
                    ))
                } else {
                    Err(error_invalid_data(
                        "Reed-Solomon recovery failed for corrupted trailer",
                    ))
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_trailer_parse_complete() {
        let blake3_hash = [0x42u8; 32];
        let trailer = SLZTrailer::new(12345, blake3_hash);

        let mut buffer = Vec::new();
        trailer.write(&mut buffer).expect("write should succeed");

        // Remove the end-of-blocks marker for parsing
        let trailer_data = &buffer[8..];
        let parsed_trailer =
            SLZTrailer::parse(Cursor::new(trailer_data)).expect("parse should succeed");

        assert_eq!(parsed_trailer.uncompressed_size, 12345);
        assert_eq!(parsed_trailer.blake3_hash, blake3_hash);
    }

    #[test]
    fn test_trailer_parse_truncated_recoverable() {
        let blake3_hash = [0x42u8; 32];
        let trailer = SLZTrailer::new(12345, blake3_hash);

        let mut buffer = Vec::new();
        trailer.write(&mut buffer).expect("write should succeed");

        // Remove the end-of-blocks marker and truncate few parity bytes (within Reed-Solomon limits)
        let trailer_data = &buffer[8..];
        let truncated_data = &trailer_data[..trailer_data.len() - 3];

        let parsed_trailer =
            SLZTrailer::parse(Cursor::new(truncated_data)).expect("truncated parse should succeed");

        assert_eq!(parsed_trailer.uncompressed_size, 12345);
    }

    #[test]
    fn test_trailer_parse_severely_truncated() {
        let blake3_hash = [0x42u8; 32];
        let trailer = SLZTrailer::new(12345, blake3_hash);

        let mut buffer = Vec::new();
        trailer.write(&mut buffer).expect("write should succeed");

        // Remove the end-of-blocks marker and truncate to only have size + partial hash
        let trailer_data = &buffer[8..];
        let severely_truncated = &trailer_data[..20];

        let result = SLZTrailer::parse(Cursor::new(severely_truncated));
        assert!(result.is_err(), "severely truncated parse should fail");
    }

    #[test]
    fn test_trailer_parse_no_parity_fails() {
        let blake3_hash = [0x42u8; 32];
        let trailer = SLZTrailer::new(12345, blake3_hash);

        let mut buffer = Vec::new();
        trailer.write(&mut buffer).expect("write should succeed");

        // Remove the end-of-blocks marker and keep only size + hash (no parity)
        let trailer_data = &buffer[8..];
        let no_parity_data = &trailer_data[..40];

        let result = SLZTrailer::parse(Cursor::new(no_parity_data));
        assert!(result.is_err(), "no parity parse should fail");
    }
}
