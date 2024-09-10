#ifndef TRANSPOSE_H
#define TRANSPOSE_H

#include "config.h"
#include "block.h"
#include "util.h"

#include "transpose_impl.h"

#define TRANSPOSE_BITS_ROWS (1 << TRANSPOSE_BITS_ROWS_SHIFT)

// Interface defined by transpose_impl.h:

// #define TRANSPOSE_BITS_ROWS_SHIFT /**/

// Treat the input as a 4x4 matrix of 32-bit values, and transpose the matrix.
ALWAYS_INLINE void transpose4x4_32(block128* output, const block128* input);

// Transpose a 4x2 (row manjor) matrix to get a 2x4 matrix. input0 contains the first two rows,
// and input1 has the other two rows.
ALWAYS_INLINE void transpose4x2_32(block128* output, block128 input0, block128 input1);

// Treat the input as a 2x2 matrix of 64-bit values, and transpose the matrix.
ALWAYS_INLINE block256 transpose2x2_64(block256 input);

// Treat the input as a 2x2 matrix of 128-bit values, and transpose the matrix.
ALWAYS_INLINE void transpose2x2_128(block256* output, block256 input0, block256 input1);

// Convert a column-major rows x SECURITY_PARAM bit matrix into row-major format. Each column must
// start stride bytes from the previous. Rows must be a multiple of TRANSPOSE_BITS_ROWS.
void transpose_secpar(const void* input, void* output, size_t stride, size_t rows);

// Treat the input as a row major 8x2 matrix of 8-bit values, and transpose the matrix.
ALWAYS_INLINE block128 transpose8x2_8(block128 x);

// Treat the input as a row major 2x8 matrix of 8-bit values, and transpose the matrix.
ALWAYS_INLINE block128 transpose2x8_8(block128 x);

// Treat the input as a row major 3x8 matrix of 8-bit values, and transpose the matrix.
ALWAYS_INLINE block192 transpose3x8_8(block192 x);

// Treat the input as a row major 4x8 matrix of 8-bit values, and transpose the matrix.
ALWAYS_INLINE block256 transpose4x8_8(block256 x);

// Treat the input as a row major 2x8 matrix of 16-bit values, and transpose the matrix.
ALWAYS_INLINE block256 transpose2x8_16(block256 x);

// Treat the input as a 8x8 matrix of 1-bit values, and transpose the matrix.
ALWAYS_INLINE uint64_t transpose8x8_1(uint64_t x);

// Treat the input as a row major 16x8 matrix of 1-bit values, and transpose the matrix.
ALWAYS_INLINE block128 transpose16x8_1(block128 x);

// Treat the input as a row major 24x8 matrix of 1-bit values, and transpose the matrix.
ALWAYS_INLINE block192 transpose24x8_1(block192 x);

// Treat the input as a row major 32x8 matrix of 1-bit values, and transpose the matrix.
ALWAYS_INLINE block256 transpose32x8_1(block256 x);

#endif
