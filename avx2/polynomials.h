#ifndef POLYNOMIALS_H
#define POLYNOMIALS_H

#include <inttypes.h>

#include <immintrin.h>
#include <wmmintrin.h>

// Polys: 64, 128, 256, 512.
// TODO: What about 192 and 384?

typedef uint64_t poly64;
typedef __m128i poly128;
typedef __m256i poly256;
typedef struct {
	__m256i l;
	__m256i h;
} poly512;

inline poly64 xor64(poly64 x, poly64 y)
{
	return x ^ y;
}
inline poly128 xor128(poly128 x, poly128 y)
{
	return _mm_xor_si128(x, y);
}
inline poly256 xor256(poly256 x, poly256 y)
{
	return _mm256_xor_si256(x, y);
}

inline poly128 mul64(poly64 x, poly64 y)
{
	return _mm_clmulepi64_si128(_mm_set_epi64x(0, x), _mm_set_epi64x(0, y), 0x00);
}

inline poly256 mul128(poly128, poly128);
inline poly512 mul256(poly256, poly256);

// Reduction for implementing GF(2**n).
inline poly64 reduce128_64(poly128 x);
inline poly128 reduce256_128(poly256 x);
inline poly256 reduce512_256(poly512 x);

// TODO: Is it faster to try to combine multiplication and reduction for all GF(2**n)
// multiplications, somehow?

#endif
