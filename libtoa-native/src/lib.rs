//! # TOA C Library Interface
//!
//! This crate provides a C-compatible interface for the TOA compression library.

use std::{io::Cursor, ptr, slice};

use libtoa::{TOAOptions, TOAStreamingDecoder, TOAStreamingEncoder, copy_wide};

/// Error codes returned by TOA C API functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TOAErrorCode {
    /// Success - no error occurred.
    Success = 0,
    /// Invalid input parameters (null pointers, zero sizes, etc.).
    InvalidInput = -1,
    /// Memory allocation failed.
    OutOfMemory = -2,
    /// Compression failed.
    CompressionError = -3,
    /// Decompression failed.
    DecompressionError = -4,
    /// Invalid compressed data format.
    InvalidData = -5,
    /// Generic I/O error.
    IoError = -6,
}

/// Result structure for compression/decompression operations.
#[repr(C)]
pub struct TOAResult {
    /// Error code (0 for success, negative for errors).
    pub error_code: TOAErrorCode,
    /// Pointer to the allocated output data (must be freed with toa_free).
    pub data: *mut u8,
    /// Size of the output data in bytes.
    pub size: usize,
}

/// Compress data using TOA compression format.
///
/// # Parameters
/// - `input`: Pointer to input data.
/// - `input_size`: Size of input data in bytes.
/// - `preset`: Compression preset level (0-9, higher = better compression).
///
/// # Returns
/// TOAResult structure containing error code, output data pointer, and size.
/// On success, the caller must free the returned data using `toa_free()`.
///
/// # Safety
/// - `input` must be valid for reads of `input_size` bytes.
/// - The returned data pointer must be freed with `toa_free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn toa_compress(
    input: *const u8,
    input_size: usize,
    preset: u32,
) -> TOAResult {
    if input.is_null() || input_size == 0 {
        return TOAResult {
            error_code: TOAErrorCode::InvalidInput,
            data: ptr::null_mut(),
            size: 0,
        };
    }

    let input_slice = unsafe { slice::from_raw_parts(input, input_size) };

    let mut output_buffer = Vec::new();

    let options = TOAOptions::from_preset(preset);

    let mut encoder = TOAStreamingEncoder::new(&mut output_buffer, options);

    match copy_wide(&mut Cursor::new(input_slice), &mut encoder) {
        Ok(_) => match encoder.finish() {
            Ok(_) => {
                // Convert Vec to boxed slice for proper memory management
                let boxed_slice = output_buffer.into_boxed_slice();
                let size = boxed_slice.len();
                let data_ptr = Box::into_raw(boxed_slice) as *mut u8;

                TOAResult {
                    error_code: TOAErrorCode::Success,
                    data: data_ptr,
                    size,
                }
            }
            Err(_) => TOAResult {
                error_code: TOAErrorCode::CompressionError,
                data: ptr::null_mut(),
                size: 0,
            },
        },
        Err(_) => TOAResult {
            error_code: TOAErrorCode::CompressionError,
            data: ptr::null_mut(),
            size: 0,
        },
    }
}

/// Decompress TOA compressed data.
///
/// # Parameters
/// - `input`: Pointer to compressed input data.
/// - `input_size`: Size of compressed input data in bytes.
///
/// # Returns
/// TOAResult structure containing error code, output data pointer, and size.
/// On success, the caller must free the returned data using `toa_free()`.
///
/// # Safety
/// - `input` must be valid for reads of `input_size` bytes.
/// - The returned data pointer must be freed with `toa_free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn toa_decompress(input: *const u8, input_size: usize) -> TOAResult {
    if input.is_null() || input_size == 0 {
        return TOAResult {
            error_code: TOAErrorCode::InvalidInput,
            data: ptr::null_mut(),
            size: 0,
        };
    }

    let input_slice = unsafe { slice::from_raw_parts(input, input_size) };

    let mut output_buffer = Vec::new();

    let mut decoder = TOAStreamingDecoder::new(input_slice, true);

    match std::io::copy(&mut decoder, &mut output_buffer) {
        Ok(_) => {
            // Convert Vec to boxed slice for proper memory management
            let boxed_slice = output_buffer.into_boxed_slice();
            let size = boxed_slice.len();
            let data_ptr = Box::into_raw(boxed_slice) as *mut u8;

            TOAResult {
                error_code: TOAErrorCode::Success,
                data: data_ptr,
                size,
            }
        }
        Err(_) => TOAResult {
            error_code: TOAErrorCode::DecompressionError,
            data: ptr::null_mut(),
            size: 0,
        },
    }
}

/// Free memory allocated by TOA functions.
///
/// # Parameters
/// - `ptr`: Pointer to memory allocated by `toa_compress()` or `toa_decompress()`.
/// - `size`: Size of the allocated memory in bytes.
///
/// # Safety
/// - `ptr` must have been returned by `toa_compress()` or `toa_decompress()`.
/// - `size` must be the exact size returned by those functions.
/// - `ptr` must not be used after calling this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn toa_free(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        let slice_ptr = ptr::slice_from_raw_parts_mut(ptr, size);
        let boxed_slice: Box<[u8]> = unsafe { Box::from_raw(slice_ptr) };
        drop(boxed_slice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_roundtrip() {
        let test_data = b"Hello, TOA compression from C API!";

        let compress_result = unsafe { toa_compress(test_data.as_ptr(), test_data.len(), 5) };

        assert_eq!(compress_result.error_code, TOAErrorCode::Success);
        assert!(!compress_result.data.is_null());
        assert!(compress_result.size > 0);

        let decompress_result =
            unsafe { toa_decompress(compress_result.data, compress_result.size) };

        assert_eq!(decompress_result.error_code, TOAErrorCode::Success);
        assert!(!decompress_result.data.is_null());
        assert_eq!(decompress_result.size, test_data.len());

        let decompressed_slice =
            unsafe { slice::from_raw_parts(decompress_result.data, decompress_result.size) };
        assert_eq!(decompressed_slice, test_data);

        unsafe {
            toa_free(compress_result.data, compress_result.size);
            toa_free(decompress_result.data, decompress_result.size);
        }
    }

    #[test]
    fn test_invalid_input() {
        let result = unsafe { toa_compress(ptr::null(), 0, 5) };
        assert_eq!(result.error_code, TOAErrorCode::InvalidInput);
        assert!(result.data.is_null());
        assert_eq!(result.size, 0);

        let result = unsafe { toa_decompress(ptr::null(), 0) };
        assert_eq!(result.error_code, TOAErrorCode::InvalidInput);
        assert!(result.data.is_null());
        assert_eq!(result.size, 0);
    }
}
