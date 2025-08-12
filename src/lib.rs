#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
mod no_std;
mod reader;
pub mod reed_solomon;
#[cfg(feature = "std")]
mod work_queue;
pub mod writer;

#[cfg(feature = "std")]
pub(crate) use std::io::Error;
#[cfg(feature = "std")]
pub(crate) use std::io::Read;
#[cfg(feature = "std")]
pub(crate) use std::io::Write;

#[cfg(not(feature = "std"))]
pub use no_std::Error;
#[cfg(not(feature = "std"))]
pub use no_std::Read;
#[cfg(not(feature = "std"))]
pub use no_std::Write;

pub use writer::{Prefilter, SLZOptions, SLZWriter};

/// Result type of the crate.
#[cfg(feature = "std")]
pub type Result<T> = core::result::Result<T, Error>;

/// Result type of the crate.
#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, Error>;

/// Helper to set the shared error state and trigger shutdown.
#[cfg(feature = "std")]
fn set_error(
    error: Error,
    error_store: &std::sync::Arc<std::sync::Mutex<Option<Error>>>,
    shutdown_flag: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut guard = error_store.lock().unwrap();
    if guard.is_none() {
        *guard = Some(error);
    }
    shutdown_flag.store(true, std::sync::atomic::Ordering::Release);
}

trait ByteReader {
    fn read_u8(&mut self) -> Result<u8>;

    fn read_u32(&mut self) -> Result<u32>;

    fn read_u64(&mut self) -> Result<u64>;
}

trait ByteWriter {
    fn write_u8(&mut self, value: u8) -> Result<()>;

    fn write_u32(&mut self, value: u32) -> Result<()>;

    fn write_u64(&mut self, value: u64) -> Result<()>;
}

impl<T: Read> ByteReader for T {
    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[inline(always)]
    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(buf.as_mut())?;
        Ok(u32::from_le_bytes(buf))
    }

    #[inline(always)]
    fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(buf.as_mut())?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl<T: Write> ByteWriter for T {
    #[inline(always)]
    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write_all(&[value])
    }

    #[inline(always)]
    fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    #[inline(always)]
    fn write_u64(&mut self, value: u64) -> Result<()> {
        self.write_all(&value.to_le_bytes())
    }
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_eof() -> Error {
    Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_other(msg: &'static str) -> Error {
    Error::other(msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_invalid_input(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::InvalidInput, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_invalid_data(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::InvalidData, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_out_of_memory(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::OutOfMemory, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn error_unsupported(msg: &'static str) -> Error {
    Error::new(std::io::ErrorKind::Unsupported, msg)
}

#[cfg(feature = "std")]
#[inline(always)]
fn copy_error(error: &Error) -> Error {
    Error::new(error.kind(), error.to_string())
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_eof() -> Error {
    Error::EOF
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_other(msg: &'static str) -> Error {
    Error::Other(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_invalid_input(msg: &'static str) -> Error {
    Error::InvalidInput(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_invalid_data(msg: &'static str) -> Error {
    Error::InvalidData(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_out_of_memory(msg: &'static str) -> Error {
    Error::OutOfMemory(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn error_unsupported(msg: &'static str) -> Error {
    Error::Unsupported(msg)
}

#[cfg(not(feature = "std"))]
#[inline(always)]
fn copy_error(error: &Error) -> Error {
    *error
}
