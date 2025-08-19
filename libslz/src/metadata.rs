use std::io::{Read, Seek, SeekFrom};

use crate::{
    Prefilter,
    header::{SLZBlockHeader, SLZHeader},
    trailer::SLZFileTrailer,
};

/// Metadata information from an SLZ file.
#[derive(Debug, Clone)]
pub struct SLZMetadata {
    /// The prefilter used in the file
    pub prefilter: Prefilter,
    /// Blocksize used
    pub block_size: u64,
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
    pub rs_parity: [u8; 24],
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

        let mut header_buffer = [0u8; 34];
        reader.read_exact(&mut header_buffer)?;

        let header = SLZHeader::parse(&header_buffer, true)?;

        let mut compressed_size = 0u64;

        let mut block_count = 0u64;

        // Parse blocks until we find the final trailer.
        loop {
            let mut buffer = [0u8; 64];
            reader.read_exact(&mut buffer)?;

            // Check bit 63 (MSB) to determine if this is a block header or final trailer.
            if (buffer[7] & 0x80) != 0 {
                let trailer_result = SLZFileTrailer::parse(&buffer, true);
                let (trailer, validated, corrected) = match trailer_result {
                    Ok(trailer) => (trailer, true, false),
                    Err(_) => {
                        // Try parsing without Reed-Solomon correction.
                        match SLZFileTrailer::parse(&buffer, false) {
                            Ok(trailer) => (trailer, false, false),
                            Err(e) => {
                                reader.seek(SeekFrom::Start(original_pos))?;
                                return Err(e);
                            }
                        }
                    }
                };

                reader.seek(SeekFrom::Start(original_pos))?;

                return Ok(SLZMetadata {
                    prefilter: header.prefilter(),
                    block_size: header.block_size(),
                    lc: header.lc(),
                    lp: header.lp(),
                    pb: header.pb(),
                    dict_size: header.dict_size(),
                    block_count,
                    uncompressed_size: trailer.total_uncompressed_size(),
                    compressed_size,
                    blake3_hash: trailer.blake3_hash(),
                    rs_parity: trailer.rs_parity(),
                    validated,
                    corrected,
                });
            } else {
                let block_header = SLZBlockHeader::parse(&buffer, true)?;
                let physical_size = block_header.physical_size();

                compressed_size += physical_size;
                block_count += 1;

                reader.seek(SeekFrom::Current(physical_size as i64))?;
            }
        }
    }
}
