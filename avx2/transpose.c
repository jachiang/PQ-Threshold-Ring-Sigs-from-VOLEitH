#include "transpose.h"

#include <string.h>
#include "vole_params.h"

// TODO: test 3 and 4
#define TRANSPOSE_CHUNK_SHIFT 4
#define TRANSPOSE_CHUNK_SIZE (1 << TRANSPOSE_CHUNK_SHIFT)

static void transposeNxNxV_8_chunk(unsigned char* matrix, size_t stride, size_t chunk_size)
{
	#ifdef __GNUC__
	#pragma GCC unroll (4)
	#endif
	for (int i = 0; i < 4; ++i)
	{
		size_t bit = 1 << i;

		#ifdef __GNUC__
		_Pragma(STRINGIZE(GCC unroll (TRANSPOSE_CHUNK_SIZE)))
		#endif
		for (size_t j = 0; j < chunk_size; ++j)
		{
			// Iterate over all j with bit i cleared.
			if (j & bit)
				continue;

			block256 in[2], out[2];
			memcpy(&in[0], &matrix[stride * j], sizeof(in[0]));
			memcpy(&in[1], &matrix[stride * (j + bit)], sizeof(in[1]));

			switch (i)
			{
			case 0:
				out[0] = _mm256_unpacklo_epi8(in[0], in[1]);
				out[1] = _mm256_unpackhi_epi8(in[0], in[1]);
				break;
			case 1:
				out[0] = _mm256_unpacklo_epi16(in[0], in[1]);
				out[1] = _mm256_unpackhi_epi16(in[0], in[1]);
				break;
			case 2:
				out[0] = _mm256_unpacklo_epi32(in[0], in[1]);
				out[1] = _mm256_unpackhi_epi32(in[0], in[1]);
				break;
			case 3:
				out[0] = _mm256_unpacklo_epi64(in[0], in[1]);
				out[1] = _mm256_unpackhi_epi64(in[0], in[1]);
				break;
			}

			memcpy(&matrix[stride * j], &out[0], sizeof(out[0]));
			memcpy(&matrix[stride * (j + bit)], &out[1], sizeof(out[1]));
		}
	}
}

// Transpose an NxN byte matrix for N = 2^size_shift equal to either 16 or 32 using unpack*
// instructions. Initially, each vector contains a contagious row (or rather
// TRANSPOSE128_VEC_WIDTH * 16 / N rows), but by the beginning of the ith iteration it instead
// zig-zags through a 2^i x 2^(size_shift-i) submatrix. Therefore, at the end it will hold a full
// column, completing the transpose.
static ALWAYS_INLINE void transposeNxNxV_8(unsigned char* matrix, size_t stride, size_t size_shift)
{
	block256 high_output[16];

	size_t chunk_size = TRANSPOSE_CHUNK_SIZE < 8 ? 8 : TRANSPOSE_CHUNK_SIZE;
	for (size_t j_high = 0; j_high < (1 << size_shift); j_high += chunk_size)
	{
		transposeNxNxV_8_chunk(&matrix[stride * j_high], stride, chunk_size);

		if (size_shift == 5)
		{
			// The i == 4 case works a bit differently, because AVX2 unpack* instructions treat each
			// 128-bit lane separately. The pair of rows i and i + 1 (for even i) needs to be transposed into rows i / 2 and i / 2 + 16.

			#ifdef __GNUC__
			_Pragma(STRINGIZE(GCC unroll (TRANSPOSE_CHUNK_SIZE / 2)))
			#endif
			for (size_t j_low = 0; j_low < chunk_size; j_low += 2)
			{
				size_t j = j_high + j_low;

				block256 in[2], out[2];
				memcpy(&in[0], &matrix[stride * j], sizeof(in[0]));
				memcpy(&in[1], &matrix[stride * (j + 1)], sizeof(in[1]));

				transpose2x2_128(&out[0], in[0], in[1]);

				memcpy(&matrix[stride * (j / 2)], &out[0], sizeof(out[0]));
				high_output[j / 2] = out[1];
			}
		}
	}

	if (size_shift == 5)
	{
		#ifdef __GNUC__
		_Pragma(STRINGIZE(GCC unroll (TRANSPOSE_CHUNK_SIZE)))
		#endif
		for (size_t j = 0; j < 16; ++j)
			memcpy(&matrix[stride * (j + 16)], &high_output[j], sizeof(high_output[j]));
	}
}

void transpose16x16xV_8(unsigned char* matrix)
{
	size_t stride = TRANSPOSE_BYTES_STRIDE;
	transposeNxNxV_8(matrix, stride, 4);
}

void transpose32x32xV_8(unsigned char* matrix)
{
	size_t stride = TRANSPOSE_BYTES_STRIDE;
	transposeNxNxV_8(matrix, stride, 5);
}

// Transpose the bits within each 8x8 matrix in a 2^(3 + rows_shift) x 2^8 bit matrix.
static ALWAYS_INLINE void transposeNx256_block8x8(
	unsigned char* matrix, size_t stride, size_t rows_shift)
{
	#ifdef __GNUC__
	#pragma GCC unroll (3)
	#endif
	for (int i = 0; i < 3; ++i)
	{
		size_t bit = 1 << i;

		#ifdef __GNUC__
		#pragma GCC unroll (32)
		#endif
		for (size_t j = 0; j < (8 << rows_shift); ++j)
		{
			if (j & bit)
				continue;

			block256 x, y, newX, newY;
			memcpy(&x, &matrix[stride*j], sizeof(x));
			memcpy(&y, &matrix[stride*(j+bit)], sizeof(y));

			// Mask consisting of alternating 2^i 0s and 2^i 1s. Least significant bit is 0.
			unsigned char mask = 0xf0;
			for (int k = 1; k >= (int) i; --k)
				mask ^= mask >> (1 << k);

			block256 diff = _mm256_xor_si256(x, _mm256_slli_epi16(y, 1 << i));
			diff = _mm256_and_si256(diff, _mm256_set1_epi8(mask));
			newX = _mm256_xor_si256(x, diff);
			newY = _mm256_xor_si256(y, _mm256_srli_epi16(diff, 1 << i));

			memcpy(&matrix[stride*j], &newX, sizeof(newX));
			memcpy(&matrix[stride*(j+bit)], &newY, sizeof(newY));
		}
	}
}

// Transpose the bits within each 8x8 bit block, using Eklundh's algorithm.
static void transposeNx256_blocks8x8(unsigned char* matrix, size_t stride, size_t size_shift)
{
	static_assert(TRANSPOSE_CHUNK_SIZE >= 8);
	for (size_t j = 0; j < (1 << size_shift); j += TRANSPOSE_CHUNK_SIZE)
		transposeNx256_block8x8(matrix + j*stride, stride, TRANSPOSE_CHUNK_SHIFT - 3);

	// TODO: Add messages to all static_assert s, to avoid needing C23.
}

// Transpose NxN bit matrices for N = 2^size_shift, which must be either 128 or 256.
static ALWAYS_INLINE void transposeNxNxV(unsigned char* matrix, size_t stride, size_t size_shift)
{
	// First transpose down to the level of bytes.
	for (size_t j = 0; j < 8; ++j)
		if (size_shift == 7)
			transpose16x16xV_8(matrix + j * stride);
		else
			transpose32x32xV_8(matrix + j * stride);

	// Then bits.
	transposeNx256_blocks8x8(matrix, stride, size_shift);
}

void transpose128x128xV(void* matrix)
{
	size_t stride = TRANSPOSE_BITS_STRIDE;
	transposeNxNxV((unsigned char*) matrix, stride, 7);
}

void transpose256x256xV(void* matrix)
{
	size_t stride = TRANSPOSE_BITS_STRIDE;
	transposeNxNxV((unsigned char*) matrix, stride, 8);
}
