#ifndef TOA_H
#define TOA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes returned by TOA C API functions.
 */
typedef enum {
    /** Success - no error occurred */
    TOA_SUCCESS = 0,
    /** Invalid input parameters (null pointers, zero sizes, etc.) */
    TOA_INVALID_INPUT = -1,
    /** Memory allocation failed */
    TOA_OUT_OF_MEMORY = -2,
    /** Compression failed */
    TOA_COMPRESSION_ERROR = -3,
    /** Decompression failed */
    TOA_DECOMPRESSION_ERROR = -4,
    /** Invalid compressed data format */
    TOA_INVALID_DATA = -5,
    /** Generic I/O error */
    TOA_IO_ERROR = -6,
} TOAErrorCode;

/**
 * @brief Result structure for compression/decompression operations.
 */
typedef struct {
    /** Error code (0 for success, negative for errors) */
    TOAErrorCode error_code;
    /** Pointer to the allocated output data (must be freed with toa_free) */
    uint8_t *data;
    /** Size of the output data in bytes */
    size_t size;
} TOAResult;

/**
 * @brief Compress data using TOA compression format.
 *
 * @param input Pointer to input data.
 * @param input_size Size of input data in bytes.
 * @param preset Compression preset level (0-9, higher = better compression).
 * @return TOAResult structure containing error code, output data pointer, and size.
 *         On success, the caller must free the returned data using toa_free().
 *
 * @note The input pointer must be valid for reads of input_size bytes.
 * @note The returned data pointer must be freed with toa_free().
 */
TOAResult toa_compress(const uint8_t *input, size_t input_size, uint32_t preset);

/**
 * @brief Decompress TOA compressed data.
 *
 * @param input Pointer to compressed input data.
 * @param input_size Size of compressed input data in bytes.
 * @return TOAResult structure containing error code, output data pointer, and size.
 *         On success, the caller must free the returned data using toa_free().
 *
 * @note The input pointer must be valid for reads of input_size bytes.
 * @note The returned data pointer must be freed with toa_free().
 */
TOAResult toa_decompress(const uint8_t *input, size_t input_size);

/**
 * @brief Free memory allocated by TOA functions.
 *
 * @param ptr Pointer to memory allocated by toa_compress() or toa_decompress().
 * @param size Size of the allocated memory in bytes.
 *
 * @note ptr must have been returned by toa_compress() or toa_decompress().
 * @note size must be the exact size returned by those functions.
 * @note ptr must not be used after calling this function.
 */
void toa_free(uint8_t *ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* TOA_H */