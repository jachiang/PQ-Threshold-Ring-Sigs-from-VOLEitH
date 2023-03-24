#ifndef POLYNOMIALS_IMPL_H
#define POLYNOMIALS_IMPL_H

#include <inttypes.h>
#include <string.h>
#include <immintrin.h>
#include <wmmintrin.h>

#include "transpose.h"

// TODO: Do we need 192 and 384 bit polynomials?

// TODO: should probably separate out most of the declarations in common between all
// implementations.

// This is twice as long as it needs to be. It is treated as a poly128_vec, with the high half of
// each 128-bit polynomial assumed to be all zeroes.
typedef clmul_block poly64_vec;

typedef clmul_block poly128_vec;
typedef struct
{
	clmul_block data[2]; // Striped in 128-bit chunks.
} poly256_vec;
typedef struct
{
	clmul_block data[4];
} poly512_vec;

inline poly64_vec poly64_vec_load(const void* s)
{
#if POLY_VEC_LEN == 1
	uint64_t in;
#elif POLY_VEC_LEN == 2
	block128 in;
#endif
	memcpy(&in, s, sizeof(in));

	poly64_vec out;
#if POLY_VEC_LEN == 1
	out = _mm_cvtsi64_si128(in);
#elif POLY_VEC_LEN == 2
	out = _mm256_inserti128_si256(_mm256_setzero_si256(), in, 0);
	out = transpose2x2_64(out);
#endif

	return out;
}

inline poly128_vec poly128_vec_load(const void* s)
{
	poly128_vec out;
	memcpy(&out, s, sizeof(out));
	return out;
}

inline poly256_vec poly256_vec_load(const void* s)
{
	poly256_vec out;

#if POLY_VEC_LEN == 1
	memcpy(&out, s, sizeof(out));

#elif POLY_VEC_LEN == 2
	block256 in[2];
	memcpy(&in[0], s, sizeof(in));
	transpose2x2_128(&out.data[0], in[0], in[1]);
#endif

	return out;
}

inline poly512_vec poly512_vec_load(const void* s)
{
	poly512_vec out;

#if POLY_VEC_LEN == 1
	memcpy(&out, s, sizeof(out));

#elif POLY_VEC_LEN == 2
	block256 in[4];
	memcpy(&in[0], s, sizeof(in));
	transpose2x2_128(&out.data[0], in[0], in[2]);
	transpose2x2_128(&out.data[2], in[1], in[3]);
#endif

	return out;
}

inline void poly64_vec_store(void* d, poly64_vec s)
{
#if POLY_VEC_LEN == 1
	uint64_t out = _mm_cvtsi128_si64(s);
#elif POLY_VEC_LEN == 2
	__m128i out = _mm256_castsi256_si128(transpose2x2_64(s));
#endif

	memcpy(d, &out, sizeof(out));
}

inline void poly128_vec_store(void* d, poly128_vec s)
{
	memcpy(d, &s, sizeof(s));
}

inline void poly256_vec_store(void* d, poly256_vec s)
{
#if POLY_VEC_LEN == 1
	memcpy(d, &s, sizeof(s));

#elif POLY_VEC_LEN == 2
	block256 out[2];
	transpose2x2_128(&out[0], s.data[0], s.data[1]);
	memcpy(d, &out[0], sizeof(out));
#endif
}

inline void poly512_vec_store(void* d, poly512_vec s)
{
#if POLY_VEC_LEN == 1
	memcpy(d, &s, sizeof(s));

#elif POLY_VEC_LEN == 2
	block256 out[4];
	transpose2x2_128(&out[0], s.data[0], s.data[1]);
	block256 tmp = out[1];
	out[1] = out[2];
	out[2] = tmp;
	memcpy(d, &out[0], sizeof(out));
#endif
}

inline poly64_vec poly64_vec_add(poly64_vec x, poly64_vec y)
{
#if POLY_VEC_LEN == 1
	return x ^ y;
#elif POLY_VEC_LEN == 2
	return block128_xor(x, y);
#endif
}
inline poly128_vec poly128_vec_add(poly128_vec x, poly128_vec y)
{
	return clmul_block_xor(x, y);
}
inline poly256_vec poly256_vec_add(poly256_vec x, poly256_vec y)
{
	poly256_vec out;
	for (size_t i = 0; i < 2; ++i)
		out.data[i] = clmul_block_xor(x.data[i], y.data[i]);
	return out;
}
inline poly512_vec poly512_vec_add(poly512_vec x, poly512_vec y)
{
	poly512_vec out;
	for (size_t i = 0; i < 4; ++i)
		out.data[i] = clmul_block_xor(x.data[i], y.data[i]);
	return out;
}

inline poly128_vec poly64_vec_mul(poly64_vec x, poly64_vec y)
{
	return clmul_block_clmul_ll(x, y);
}

inline poly256_vec poly128_vec_mul(poly128_vec x, poly128_vec y)
{
	// Karatsuba multiplication.
	clmul_block x0y0 = clmul_block_clmul_ll(x, y);
	clmul_block x1y1 = clmul_block_clmul_hh(x, y);
	clmul_block x1_cat_y0 = clmul_block_mix_64(y, x);
	clmul_block x0_plus_x1 = poly128_vec_add(x, x1_cat_y0); // Result in low.
	clmul_block y0_plus_y1 = poly128_vec_add(y, x1_cat_y0); // Result in high.
	clmul_block x0_plus_x1_y0_plus_y1 = clmul_block_clmul_lh(x0_plus_x1, y0_plus_y1);
	clmul_block x0y1_plus_x1y0 = poly128_vec_add(poly128_vec_add(x0y0, x1y1), x0_plus_x1_y0_plus_y1);

	// TODO: Is there a way to combine the left and right shifts?

	poly256_vec out;
	out.data[0] = poly128_vec_add(x0y0, clmul_block_shift_left_64(x0y1_plus_x1y0));
	out.data[1] = poly128_vec_add(x1y1, clmul_block_shift_right_64(x0y1_plus_x1y0));
	return out;
}

inline poly512_vec poly256_vec_mul(poly256_vec x, poly256_vec y)
{
	// Karatsuba multiplication.
	poly256_vec x0y0 = poly128_vec_mul(x.data[0], y.data[0]);
	poly256_vec x1y1 = poly128_vec_mul(x.data[1], y.data[1]);
	poly128_vec x0_plus_y0 = poly128_vec_add(x.data[0], y.data[0]);
	poly128_vec x1_plus_y1 = poly128_vec_add(x.data[1], y.data[1]);
	poly256_vec x0_plus_x1_y0_plus_y1 = poly128_vec_mul(x.data[1], y.data[1]);
	poly256_vec x0y1_plus_x1y0 = poly256_vec_add(poly256_vec_add(x0y0, x1y1), x0_plus_x1_y0_plus_y1);

	// TODO: Is there a way to combine the left and right shifts?

	poly512_vec out;
	out.data[0] = x0y0.data[0];
	out.data[1] = poly128_vec_add(x0y0.data[1], x0y1_plus_x1y0.data[0]);
	out.data[2] = poly128_vec_add(x1y1.data[0], x0y1_plus_x1y0.data[1]);
	out.data[3] = x1y1.data[1];
	return out;
}

// Modulus for GF(2^n), without the x^n term.
const extern uint32_t gf64_modulus;  // degree = 4
const extern uint32_t gf128_modulus; // degree = 7
const extern uint32_t gf256_modulus; // degree = 10

// TODO: May be cheaper to keep gf*_modulus in uint32_ts, then load with a broadcast and blend with
// zero.

inline clmul_block load_u32_into_vector(uint32_t x)
{
#if POLY_VEC_LEN == 1
	return _mm_cvtsi32_si128(x);
#elif POLY_VEC_LEN == 2
	return _mm256_blend_epi32(_mm256_setzero_si256(), _mm256_set1_epi32(x), 0x11);
#endif
}

inline poly64_vec get_gf64_modulus()
{
	return load_u32_into_vector(gf64_modulus);
}

inline poly128_vec get_gf128_modulus()
{
	return load_u32_into_vector(gf128_modulus);
}

inline poly256_vec get_gf256_modulus()
{
	poly256_vec out;
	out.data[0] = load_u32_into_vector(gf128_modulus);
	out.data[1] = clmul_block_set_all_8(0);
	return out;
}

// Reduction for implementing GF(2**n).
inline poly64_vec poly128_vec_reduce64(poly128_vec x);
inline poly128_vec poly256_vec_reduce128(poly256_vec x);
inline poly256_vec poly512_vec_reduce256(poly512_vec x);

#endif
