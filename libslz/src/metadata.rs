use std::io::{Read, Seek, SeekFrom};

use crate::{
    ByteReader, Prefilter, SLZ_MAGIC, SLZ_VERSION, error_invalid_data, error_unsupported,
    reed_solomon,
};

/// Metadata information from an SLZ file.
#[derive(Debug, Clone)]
pub struct SLZMetadata {
    /// The prefilter used in the file
    pub prefilter: Prefilter,
    /// LZMA literal context bits
    pub lc: u8,
    /// LZMA literal position bits
    pub lp: u8,
    /// LZMA position bits
    pub pb: u8,
    /// Dictionary size used
    pub dict_size: u32,
    /// Number of compressed blocks in the file
    pub block_count: u64,
    /// Total uncompressed size of all data
    pub uncompressed_size: u64,
    /// Total compressed size of all data (excluding header and trailer)
    pub compressed_size: u64,
    /// Blake3 hash of the uncompressed data
    pub blake3_hash: [u8; 32],
    /// Reed-Solomon parity data for hash protection
    pub rs_parity: [u8; 32],
    /// `True` if the hash could be validated
    pub validated: bool,
    /// `True` if the hash was corrupt but could be validated.
    pub corrected: bool,
}

impl SLZMetadata {
    /// Read SLZ file metadata from a seekable reader.
    ///
    /// This function reads and validates the header and trailer of an SLZ file,
    /// returning metadata about the compression parameters and file sizes.
    /// The reader position is preserved.
    #[cfg(feature = "std")]
    pub fn parse<R: Read + Seek>(mut reader: R) -> crate::Result<SLZMetadata> {
        let original_pos = reader.stream_position()?;

        reader.seek(SeekFrom::Start(0))?;

        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != SLZ_MAGIC {
            reader.seek(SeekFrom::Start(original_pos))?;
            return Err(error_invalid_data("invalid SLZ magic bytes"));
        }

        let version = reader.read_u8()?;
        if version != SLZ_VERSION {
            reader.seek(SeekFrom::Start(original_pos))?;
            return Err(error_unsupported("unsupported SLZ version"));
        }

        let prefilter_byte = reader.read_u8()?;
        let prefilter = match prefilter_byte {
            0x00 => Prefilter::None,
            0x01 => {
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
            _ => {
                reader.seek(SeekFrom::Start(original_pos))?;
                return Err(error_invalid_data("unsupported prefilter type"));
            }
        };

        let props = reader.read_u8()?;
        let lc = props % 9;
        let temp = props / 9;
        let lp = temp % 5;
        let pb = temp / 5;

        if lc > 8 || lp > 4 || pb > 4 {
            reader.seek(SeekFrom::Start(original_pos))?;
            return Err(error_invalid_data("invalid LZMA properties"));
        }

        let dict_size_log2 = reader.read_u8()?;
        if dict_size_log2 > 16 {
            reader.seek(SeekFrom::Start(original_pos))?;
            return Err(error_invalid_data("invalid dictionary size"));
        }
        let dict_size = 2u32.pow((dict_size_log2 + 16) as u32);

        let mut compressed_size = 0u64;

        let mut block_count = 0u64;
        loop {
            let block_size = reader.read_u64()?;
            if block_size == 0 {
                // End-of-blocks marker found
                break;
            }
            compressed_size += block_size;
            block_count += 1;

            // Skip the compressed data and the 72-byte block trailer
            reader.seek(SeekFrom::Current(block_size as i64 + 72))?;
        }

        // 72 bytes for trailer
        reader.seek(SeekFrom::End(-72))?;

        let uncompressed_size = reader.read_u64()?;

        let mut blake3_hash = [0u8; 32];
        reader.read_exact(&mut blake3_hash)?;

        let mut rs_parity = [0u8; 32];
        reader.read_exact(&mut rs_parity)?;

        let mut codeword = [0u8; 64];
        codeword[..32].copy_from_slice(&blake3_hash);
        codeword[32..].copy_from_slice(&rs_parity);

        let mut validated = true;
        let mut corrected = false;

        match reed_solomon::decode(&mut codeword) {
            Ok(was_corrected) => {
                if was_corrected {
                    blake3_hash.copy_from_slice(&codeword[..32]);
                    corrected = true;
                }
            }
            Err(_) => {
                reader.seek(SeekFrom::Start(original_pos))?;
                validated = false;
            }
        }

        reader.seek(SeekFrom::Start(original_pos))?;

        Ok(SLZMetadata {
            prefilter,
            lc,
            lp,
            pb,
            dict_size,
            block_count,
            uncompressed_size,
            compressed_size,
            blake3_hash,
            rs_parity,
            validated,
            corrected,
        })
    }
}
