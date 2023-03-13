#ifndef POLYNOMIALS_H
#define POLYNOMIALS_H

#include <inttypes.h>

#include <immintrin.h>
#include <wmmintrin.h>

// Polys: 64, 128, 256, 512.

typedef uint64_t poly64;
typedef __m128i poly64x2;
typedef __m128i poly128;
typedef __m256i poly128x2;
typedef __m256i poly256;
typedef struct
{
	__m256i l;
	__m256i h;
} poly512;

inline poly64 xor64(poly64 x, poly64 y)
{
	return x ^ y;
}
inline poly64x2 xor64x2(poly64x2 x, poly64x2 y)
{
	return _mm_xor_si128(x, y);
}
inline poly128 xor128(poly128 x, poly128 y)
{
	return _mm_xor_si128(x, y);
}
inline poly128x2 xor128x2(poly128x2 x, poly128x2 y)
{
	return _mm256_xor_si256(x, y);
}
inline poly256 xor256(poly256 x, poly256 y)
{
	return _mm256_xor_si256(x, y);
}
inline poly512 xor512(poly512 x, poly512 y)
{
	poly512 out;
	out.l = _mm256_xor_si256(x.l, y.l);
	out.h = _mm256_xor_si256(x.h, y.h);
	return out;
}

inline poly128 mul64(poly64 x, poly64 y)
{
	return _mm_clmulepi64_si128(_mm_set_epi64x(0, x), _mm_set_epi64x(0, y), 0x00);
}

inline poly128x2 mul64x2(poly64x2 x, poly64x2 y)
{
	return _mm256_clmulepi64_epi128(_mm256_castsi128_si256(x), _mm256_castsi128_si256(y), 0x00);
}

inline poly256 mul128(poly128 x, poly128 y);
{
	// Karatsuba multiplication.
	__m128i x0y0 = _mm_clmulepi64_si128(x, y, 0x00);
	__m128i x1y1 = _mm_clmulepi64_si128(x, y, 0x11);
	__m128i x1_cat_y0 = _mm_alignr_epi8(y, x, 8);
	__m128i x0_xor_x1 = _mm_xor_si128(x, x1_cat_y0); // Result in [0].
	__m128i y0_xor_y1 = _mm_xor_si128(y, x1_cat_y0); // Result in [1].
	__m128i x0_xor_x1_y0_xor_y1 = _mm_clmulepi64_si128(x0_xor_x1, y0_xor_y1, 0x10);
	__m128i x0y1_xor_x1y0 = _mm_xor_si128(_mm_xor_si128(x0y0, x1y1), x0_xor_x1_y0_xor_y1);

	// Combine into one 256 bit polynomial.
	__m256i x0y0_cat_x1y1 = _mm256_setr_m128i(x0y0, x1y1);
	__m256i x0y1_xor_x1y0_shift_64 =
		_mm256_permute4x64_epi64(_mm256_castsi128_si256(x0y1_xor_x1y0), 0x50);
	__m256i result = _mm256_xor_si256(x0y0_cat_x1y1, x0y1_xor_x1y0_shift_64);
	result = _mm256_blend_epi32(x0y0_cat_x1y1, result, 0x3c)
	return result;
}

inline poly512 mul256(poly256 x, poly256 y)
{
	// Karatsuba multiplication.
	__m256i x1_cat_y0 = _mm256_permute2f128_si256(x, y, 0x21);
	__m256i x0_xor_x1 = _mm_xor_si256(x, x1_cat_y0); // Result in [0].
	__m256i y0_xor_y1 = _mm_xor_si256(y, x1_cat_y0); // Result in [1].

	// TODO
}

// Reduction for implementing GF(2**n).
inline poly64 reduce128_64(poly128 x);
inline poly128 reduce256_128(poly256 x);
inline poly256 reduce512_256(poly512 x);

const extern poly64 gf64_modulus;
const extern poly128 gf128_modulus;
const extern poly256 gf256_modulus;

#endif
