mod encoder;
mod encoder_fast;
mod encoder_normal;
mod lzma_writer;
mod range_enc;

use alloc::vec::Vec;

pub use encoder::EncodeMode;
use lz::MFType;
pub use lzma_writer::*;

use super::*;

/// Encoder settings when compressing with LZMA and LZMA2.
#[derive(Debug, Clone)]
pub struct LZMAOptions {
    /// Dictionary size in bytes.
    pub dict_size: u32,
    /// Number of literal context bits (0-8).
    pub lc: u32,
    /// Number of literal position bits (0-4).
    pub lp: u32,
    /// Number of position bits (0-4).
    pub pb: u32,
    /// Compression mode.
    pub mode: EncodeMode,
    /// Match finder nice length.
    pub nice_len: u32,
    /// Match finder type.
    pub mf: MFType,
    /// Match finder depth limit.
    pub depth_limit: i32,
    /// Preset dictionary data.
    pub preset_dict: Option<Vec<u8>>,
}

impl Default for LZMAOptions {
    fn default() -> Self {
        Self::with_preset(6)
    }
}

impl LZMAOptions {
    /// Default number of literal context bits.
    pub const LC_DEFAULT: u32 = 3;

    /// Default number of literal position bits.
    pub const LP_DEFAULT: u32 = 0;

    /// Default number of position bits.
    pub const PB_DEFAULT: u32 = 2;

    /// Maximum match finder nice length.
    pub const NICE_LEN_MAX: u32 = 273;

    const PRESET_TO_DICT_SIZE: &'static [u32] = &[
        1 << 18,
        1 << 20,
        1 << 21,
        1 << 22,
        1 << 22,
        1 << 23,
        1 << 23,
        1 << 24,
        1 << 25,
        1 << 26,
    ];

    const PRESET_TO_DEPTH_LIMIT: &'static [i32] = &[4, 8, 24, 48];

    /// preset: [0..9]
    #[inline]
    pub fn with_preset(preset: u32) -> Self {
        let mut opt = Self {
            dict_size: Default::default(),
            lc: Default::default(),
            lp: Default::default(),
            pb: Default::default(),
            mode: EncodeMode::Normal,
            nice_len: Default::default(),
            mf: Default::default(),
            depth_limit: Default::default(),
            preset_dict: Default::default(),
        };
        opt.set_preset(preset);
        opt
    }

    /// preset: [0..9]
    pub fn set_preset(&mut self, preset: u32) {
        let preset = preset.min(9);

        self.lc = Self::LC_DEFAULT;
        self.lp = Self::LP_DEFAULT;
        self.pb = Self::PB_DEFAULT;
        self.dict_size = Self::PRESET_TO_DICT_SIZE[preset as usize];
        if preset <= 3 {
            self.mode = EncodeMode::Fast;
            self.mf = MFType::HC4;
            self.nice_len = if preset <= 1 { 128 } else { Self::NICE_LEN_MAX };
            self.depth_limit = Self::PRESET_TO_DEPTH_LIMIT[preset as usize];
        } else {
            self.mode = EncodeMode::Normal;
            self.mf = MFType::BT4;
            self.nice_len = if preset == 4 {
                16
            } else if preset == 5 {
                32
            } else {
                64
            };
            self.depth_limit = 0;
        }
    }

    /// Returns the LZMA properties byte for these options.
    #[inline(always)]
    pub fn get_props(&self) -> u8 {
        ((self.pb * 5 + self.lp) * 9 + self.lc) as u8
    }
}
