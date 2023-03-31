#ifndef TRANSPOSE_H
#define TRANSPOSE_H

#include "config.h"
#include "block.h"
#include "util.h"

#define TRANSPOSE_BITS_STRIDE VOLE_COL_STRIDE
#define TRANSPOSE_BYTES_STRIDE (VOLE_COL_STRIDE * 8)

#include "transpose_impl.h"

// Interface defined by transpose_impl.h:

// #define TRANSPOSE128_VEC_WIDTH /**/
// #define TRANSPOSE256_VEC_WIDTH /**/

// Treat the input as a 4x4 matrix of 32-bit values, and transpose the matrix.
ALWAYS_INLINE void transpose4x4_32(block128* output, const block128* input);

// Transpose a 4x2 (row manjor) matrix to get a 2x4 matrix. input0 contains the first two rows,
// and input1 has the other two rows.
ALWAYS_INLINE void transpose4x2_32(block128* output, block128 input0, block128 input1);

// Treat the input as a 2x2 matrix of 64-bit values, and transpose the matrix.
ALWAYS_INLINE block256 transpose2x2_64(block256 input);

// Treat the input as a 2x2 matrix of 128-bit values, and transpose the matrix.
ALWAYS_INLINE void transpose2x2_128(block256* output, block256 input0, block256 input1);

// Transpose each 16x16 block of a 16 x 16*V byte matrix, stored in row-major order, where V is
// TRANSPOSE128_VEC_WIDTH. The distance (in bytes) between rows is stride = TRANSPOSE_BYTES_STRIDE.
void transpose16x16xV_8(unsigned char* matrix);

// Transpose each 32x32 block of a 32 x 32*V byte matrix, stored in row-major order, where V is
// TRANSPOSE256_VEC_WIDTH. The distance (in bytes) between rows is stride = TRANSPOSE_BYTES_STRIDE.
void transpose32x32xV_8(unsigned char* matrix);

// Transpose each 128x128 block of a 128 x 128*V bit matrix, stored in row-major order, where V is
// TRANSPOSE128_VEC_WIDTH. The distance (in bytes) between rows is stride = TRANSPOSE_BITS_STRIDE.
void transpose128x128xV(void* matrix);

// Transpose each 256x256 block of a 256 x 256*V bit matrix, stored in row-major order, where V is
// TRANSPOSE256_VEC_WIDTH. The distance (in bytes) between rows is stride = TRANSPOSE_BITS_STRIDE.
void transpose256x256xV(void* matrix);

#endif
