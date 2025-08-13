mod streaming_writer;

use core::num::NonZeroU32;

pub use streaming_writer::SLZStreamingWriter;

use crate::{
    Prefilter, Write,
    lzma::{EncodeMode, lz::MFType},
};

/// Options for SLZ compression.
#[derive(Debug, Clone, Copy)]
pub struct SLZOptions {
    /// Prefilter to apply before compression.
    prefilter: Prefilter,
    /// Dictionary size to use for the LZMA compression algorithm as a power of two.
    dictionary_size_log2: u8,
    /// LZMA literal context bits (0-8).
    lc: u8,
    /// LZMA literal position bits (0-4).
    lp: u8,
    /// LZMA position bits (0-4).
    pb: u8,
    /// Compression mode.
    pub mode: EncodeMode,
    /// Match finder nice length.
    pub nice_len: u16,
    /// Match finder type.
    pub mf: MFType,
    /// Match finder depth limit.
    pub depth_limit: u8,
    /// Block size in bytes. If None, all data will be written in blocks of 4 GiB - 1 B;
    block_size: Option<NonZeroU32>,
}

impl Default for SLZOptions {
    fn default() -> Self {
        Self {
            prefilter: Prefilter::None,
            dictionary_size_log2: 26,
            lc: 3,
            lp: 0,
            pb: 2,
            mode: EncodeMode::Normal,
            nice_len: 64,
            mf: MFType::BT4,
            depth_limit: 0,
            block_size: None,
        }
    }
}

impl SLZOptions {
    const PRESET_TO_DICT_SIZE_LOG2: &'static [u8] = &[
        18, // 256 KiB
        20, // 1 MiB
        21, // 2 MiB
        22, // 4 MiB
        22, // 4 MiB
        23, // 8 MiB
        23, // 8 MiB
        24, // 16 MiB
        25, // 32 MiB
        26, // 64 MiB
    ];

    const PRESET_TO_DEPTH_LIMIT: &'static [u8] = &[4, 8, 24, 48];

    /// Create options with a specific preset level (0-9).
    pub fn from_preset(preset: u32) -> Self {
        let preset = preset.min(9);

        let prefilter = Prefilter::None;
        let lc = 3;
        let lp = 0;
        let pb = 2;
        let dictionary_size_log2 = Self::PRESET_TO_DICT_SIZE_LOG2[preset as usize];
        let block_size = NonZeroU32::new(u32::MAX);

        let mode;
        let mf;
        let nice_len;
        let depth_limit;

        if preset <= 3 {
            mode = EncodeMode::Fast;
            mf = MFType::HC4;
            nice_len = if preset <= 1 { 128 } else { 273 };
            depth_limit = Self::PRESET_TO_DEPTH_LIMIT[preset as usize];
        } else {
            mode = EncodeMode::Normal;
            mf = MFType::BT4;
            nice_len = if preset == 4 {
                16
            } else if preset == 5 {
                32
            } else {
                64
            };
            depth_limit = 0;
        }

        Self {
            prefilter,
            dictionary_size_log2,
            lc,
            lp,
            pb,
            mode,
            nice_len,
            mf,
            depth_limit,
            block_size,
        }
    }

    /// Sets the LZMA literal context bits.
    ///
    /// Clamped in range of 0 and 8.
    pub fn with_lc(mut self, lc: u8) -> Self {
        self.lc = lc.clamp(0, 8);
        self
    }

    /// Sets the LZMA literal position bits.
    ///
    /// Clamped in range of 0 and 4.
    pub fn with_lp(mut self, lp: u8) -> Self {
        self.lp = lp.clamp(0, 4);
        self
    }

    /// Sets the LZMA position bits (0-4).
    ///
    /// Clamped in range of 0 and 4.
    pub fn with_pb(mut self, pb: u8) -> Self {
        self.pb = pb.clamp(0, 4);
        self
    }

    /// Set the prefilter to use.
    ///
    /// Delta filter distance will be clamped in range of 1 and 256.
    pub fn with_prefilter(mut self, prefilter: Prefilter) -> Self {
        let mut prefilter = prefilter;

        if let Prefilter::Delta { distance } = &mut prefilter {
            *distance = (*distance).clamp(1, 256);
        }

        self.prefilter = prefilter;
        self
    }

    /// Set the dictionary size of the LZMA compression algorithm.
    ///
    /// Clamped in range of 16 (64 KiB) and 32 (4 GiB).
    pub fn with_dictionary_size(mut self, dictionary_size_log2: u8) -> Self {
        self.dictionary_size_log2 = dictionary_size_log2.clamp(16, 32);
        self
    }

    /// Set the block size for multi-block compression.
    pub fn with_block_size(mut self, block_size: Option<NonZeroU32>) -> Self {
        self.block_size = block_size;
        self
    }

    /// Get dictionary size in bytes.
    pub fn dict_size(&self) -> u32 {
        2u32.pow(self.dictionary_size_log2 as u32)
    }
}

/// A writer that counts the bytes written (uncompressed data).
struct CountingWriter<W> {
    inner: W,
    count: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, count: 0 }
    }

    fn bytes_written(&self) -> u64 {
        self.count
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        let bytes_written = self.inner.write(buf)?;
        self.count += bytes_written as u64;
        Ok(bytes_written)
    }

    fn flush(&mut self) -> crate::Result<()> {
        self.inner.flush()
    }
}
