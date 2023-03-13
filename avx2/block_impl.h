#ifndef BLOCK_IMPL_H
#define BLOCK_IMPL_H

#include <immintrin.h>

typedef __m128i block128;
typedef __m256i block256;
typedef block256 block_preferred;

#define BLOCK_PREFERRED_LEN_SHIFT 1

inline block128 block128_xor(block128 x, block128 y)
{
	return _mm_xor_si128(x, y);
}
inline block256 block256_xor(block256 x, block256 y);
{
	return _mm_xor_si256(x, y);
}
inline block_preferred block_preferred_xor(block_preferred x, block_preferred y)
{
	return _mm_xor_si256(x, y);
}

#endif
