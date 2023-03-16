#ifndef BLOCK_IMPL_H
#define BLOCK_IMPL_H

#include <immintrin.h>

typedef __m128i block128;
typedef __m256i block256;
typedef struct
{
	block128 data[3];
} block384;
typedef struct
{
	block256 data[2];
} block512;

inline block128 block128_xor(block128 x, block128 y) { return _mm_xor_si128(x, y); }
inline block256 block256_xor(block256 x, block256 y) { return _mm256_xor_si256(x, y); }
inline block128 block128_and(block128 x, block128 y) { return _mm_and_si128(x, y); }
inline block256 block256_and(block256 x, block256 y) { return _mm256_and_si256(x, y); }
inline block128 block128_set_all_8(uint8_t x) { return _mm_set1_epi8(x); }
inline block256 block256_set_all_8(uint8_t x) { return _mm256_set1_epi8(x); }
inline block128 block128_set_low64(uint64_t x) { return _mm_set_epi64x(0, x); }
inline block256 block256_set_low64(uint64_t x) { return _mm256_setr_epi64x(x, 0, 0, 0); }
inline block256 block256_set_128(block128 x0, block128 x1) { return _mm256_setr_m128i(x0, x1); }

inline block384 block384_xor(block384 x, block384 y)
{
	block384 out;
	out.data[0] = block128_xor(x.data[0], y.data[0]);
	out.data[1] = block128_xor(x.data[1], y.data[1]);
	out.data[2] = block128_xor(x.data[2], y.data[2]);
	return out;
}
inline block512 block512_xor(block512 x, block512 y)
{
	block512 out;
	out.data[0] = block256_xor(x.data[0], y.data[0]);
	out.data[1] = block256_xor(x.data[1], y.data[1]);
	return out;
}

inline block384 block384_and(block384 x, block384 y)
{
	block384 out;
	out.data[0] = block128_and(x.data[0], y.data[0]);
	out.data[1] = block128_and(x.data[1], y.data[1]);
	out.data[2] = block128_and(x.data[2], y.data[2]);
	return out;
}
inline block512 block512_and(block512 x, block512 y)
{
	block512 out;
	out.data[0] = block256_and(x.data[0], y.data[0]);
	out.data[1] = block256_and(x.data[1], y.data[1]);
	return out;
}

inline block384 block384_set_all_8(uint8_t x)
{
	block384 out;
	out.data[0] = block128_set_all_8(x);
	out.data[1] = block128_set_all_8(x);
	out.data[2] = block128_set_all_8(x);
	return out;
}
inline block512 block512_set_all_8(uint8_t x)
{
	block512 out;
	out.data[0] = block256_set_all_8(x);
	out.data[1] = block256_set_all_8(x);
	return out;
}

inline block384 block384_set_low64(uint64_t x)
{
	block384 out;
	out.data[0] = block128_set_low64(x);
	return out;
}
inline block512 block512_set_low64(uint64_t x)
{
	block512 out;
	out.data[0] = block256_set_low64(x);
	return out;
}

#define VOLE_BLOCK_SHIFT 1
typedef block256 vole_block;
inline vole_block vole_block_xor(vole_block x, vole_block y) { return block256_xor(x, y); }
inline vole_block vole_block_and(vole_block x, vole_block y) { return block256_and(x, y); }
inline vole_block vole_block_set_all_8(uint8_t x) { return block256_set_all_8(x); }
inline vole_block vole_block_set_low64(uint64_t x) { return block256_set_low64(x); }

#endif
