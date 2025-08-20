mod ecc_reader;
mod streaming_reader;

pub use streaming_reader::SLZStreamingReader;

use crate::{
    ErrorCorrection, Prefilter, Read, Result,
    lzma::{filter::bcj::BCJReader, lzma_reader::LZMAReader, optimized_reader::OptimizedReader},
    reader::ecc_reader::ECCReader,
};

/// All possible reader combinations.
#[allow(clippy::large_enum_variant)]
enum Reader<R> {
    Lzma(LZMAReader<ECCReader<R>>),
    BcjX86(BCJReader<LZMAReader<ECCReader<R>>>),
    BcjArm(BCJReader<LZMAReader<ECCReader<R>>>),
    BcjArmThumb(BCJReader<LZMAReader<ECCReader<R>>>),
    BcjArm64(BCJReader<LZMAReader<ECCReader<R>>>),
    BcjSparc(BCJReader<LZMAReader<ECCReader<R>>>),
    BcjPowerPc(BCJReader<LZMAReader<ECCReader<R>>>),
    BcjIa64(BCJReader<LZMAReader<ECCReader<R>>>),
    BcjRiscV(BCJReader<LZMAReader<ECCReader<R>>>),
}

impl<R: OptimizedReader> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Reader::Lzma(reader) => reader.read(buf),
            Reader::BcjX86(reader) => reader.read(buf),
            Reader::BcjArm(reader) => reader.read(buf),
            Reader::BcjArmThumb(reader) => reader.read(buf),
            Reader::BcjArm64(reader) => reader.read(buf),
            Reader::BcjSparc(reader) => reader.read(buf),
            Reader::BcjPowerPc(reader) => reader.read(buf),
            Reader::BcjIa64(reader) => reader.read(buf),
            Reader::BcjRiscV(reader) => reader.read(buf),
        }
    }
}

impl<R: OptimizedReader> Reader<R> {
    /// Create a new reader chain based on the header configuration.
    fn new(
        reader: R,
        prefilter: Prefilter,
        error_correction: ErrorCorrection,
        validate_rs: bool,
        lc: u8,
        lp: u8,
        pb: u8,
        dict_size: u32,
    ) -> Result<Self> {
        let ecc_reader = ECCReader::new(reader, error_correction, validate_rs);

        let lzma_reader = LZMAReader::new(
            ecc_reader,
            u64::MAX,
            lc as u32,
            lp as u32,
            pb as u32,
            dict_size,
            None,
        )?;

        #[rustfmt::skip]
        let chain = match prefilter {
            Prefilter::None => Reader::Lzma(lzma_reader),
            Prefilter::BcjX86 => Reader::BcjX86(BCJReader::new_x86(lzma_reader, 0)),
            Prefilter::BcjArm => Reader::BcjArm(BCJReader::new_arm(lzma_reader, 0)),
            Prefilter::BcjArmThumb => Reader::BcjArmThumb(BCJReader::new_arm_thumb(lzma_reader, 0)),
            Prefilter::BcjArm64 => Reader::BcjArm64(BCJReader::new_arm64(lzma_reader, 0)),
            Prefilter::BcjSparc => Reader::BcjSparc(BCJReader::new_sparc(lzma_reader, 0)),
            Prefilter::BcjPowerPc => Reader::BcjPowerPc(BCJReader::new_ppc(lzma_reader, 0)),
            Prefilter::BcjIa64 => Reader::BcjIa64(BCJReader::new_ia64(lzma_reader, 0)),
            Prefilter::BcjRiscV => Reader::BcjRiscV(BCJReader::new_riscv(lzma_reader, 0)),
        };

        Ok(chain)
    }

    /// Extract the inner reader from the reader chain.
    fn into_inner(self) -> R {
        match self {
            Reader::Lzma(reader) => reader.into_inner().into_inner(),
            Reader::BcjX86(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjArm(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjArmThumb(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjArm64(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjSparc(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjPowerPc(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjIa64(reader) => reader.into_inner().into_inner().into_inner(),
            Reader::BcjRiscV(reader) => reader.into_inner().into_inner().into_inner(),
        }
    }
}
