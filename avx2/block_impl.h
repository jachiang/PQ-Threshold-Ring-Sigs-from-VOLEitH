#ifndef BLOCK_IMPL_AVX2_H
#define BLOCK_IMPL_AVX2_H

#include <immintrin.h>
#include <wmmintrin.h>
#include <string.h>

#include "util.h"

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

// Unfortunately, there's no alternative version of these that works on integers.
#define shuffle_2x4xepi32(x, y, i) \
	_mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(x), _mm_castsi128_ps(y), i))
#define permute_8xepi32(x, i) \
	_mm256_castps_si256(_mm256_permute_ps(_mm256_castsi256_ps(x), i))
#define shuffle_2x4xepi64(x, y, i) \
	_mm256_castpd_si256(_mm256_shuffle_pd(_mm256_castsi256_pd(x), _mm256_castsi256_pd(y), i))


// ##################################################################################################################
// ################################### TAKEN FROM THE RAINIER IMPLEMENTATION ########################################
// ##################################################################################################################


inline __m256i mm256_compute_mask_2(const uint64_t idx, const size_t bit) {
  const uint64_t m1 = -((idx >> bit) & 1);
  const uint64_t m2 = -((idx >> (bit + 1)) & 1);
  return _mm256_set_epi64x(m2, m2, m1, m1);
}
inline __m256i mm256_compute_mask(const uint64_t idx, const size_t bit) {
  return _mm256_set1_epi64x(-((idx >> bit) & 1));
}

// ################### 128 ####################
inline __m128i* block128_as_m128i(block128* block) {
  return (__m128i*)block;
}
inline void clmul_schoolbook128(__m128i out[2], const __m128i a, const __m128i b) {
  __m128i tmp[3];
  out[0] = _mm_clmulepi64_si128(a, b, 0x00);
  out[1] = _mm_clmulepi64_si128(a, b, 0x11);
  tmp[0] = _mm_clmulepi64_si128(a, b, 0x01);
  tmp[1] = _mm_clmulepi64_si128(a, b, 0x10);
  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);
  out[0] = _mm_xor_si128(out[0], tmp[1]);
  out[1] = _mm_xor_si128(out[1], tmp[2]);
}
inline void reduce_clmul128(__m128i out[1], const __m128i in[2]) {
  __m128i p = _mm_set_epi64x(0x0, 0x87);
  __m128i t0, t1, t2;
  t0 = _mm_clmulepi64_si128(in[1], p, 0x01); // in[1]_high * p
  t1 = _mm_slli_si128(t0, 8);    // low 64bit of result, shifted to high
  t2 = _mm_srli_si128(t0, 8);    // high 64bit of result, shifted to high
  t2 = _mm_xor_si128(t2, in[1]); // update in[1]_low with high64 of result
  t0 = _mm_clmulepi64_si128(t2, p, 0x00); // updated in[1]_low * p
  out[0] = _mm_xor_si128(t0, in[0]);      // add in[1]_low * p to result
  out[0] = _mm_xor_si128(out[0], t1); // also add the low part of in[1]_high * p
}
inline void sqr128(__m128i out[2], const __m128i a) {
  __m128i tmp[2];
  __m128i sqrT = _mm_set_epi64x(0x5554515045444140, 0x1514111005040100);
  __m128i mask = _mm_set_epi64x(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F);
  tmp[0] = _mm_and_si128(a, mask);
  tmp[1] = _mm_srli_epi64(a, 4);
  tmp[1] = _mm_and_si128(tmp[1], mask);
  tmp[0] = _mm_shuffle_epi8(sqrT, tmp[0]);
  tmp[1] = _mm_shuffle_epi8(sqrT, tmp[1]);
  out[0] = _mm_unpacklo_epi8(tmp[0], tmp[1]);
  out[1] = _mm_unpackhi_epi8(tmp[0], tmp[1]);
}
inline void gf128sqr(__m128i *out, const __m128i in) {
  __m128i tmp[2];
  sqr128(tmp, in);
  reduce_clmul128(out, tmp);
}
inline void gf128mul(__m128i *out, const __m128i in1, const __m128i in2) {
  __m128i tmp[2];
  clmul_schoolbook128(tmp, in1, in2);
  reduce_clmul128(out, tmp);
}
inline void block128_inverse(block128* block) {
  const size_t u[11] = {1, 2, 3, 6, 12, 24, 48, 51, 63, 126, 127};
  // q = u[i] - u[i - 1] should give us the corresponding values
  // (1, 1, 3, 6, 12, 24, 3, 12, 63, 1), which will have corresponding indexes
  const size_t q_index[10] = {0, 0, 2, 3, 4, 5, 2, 4, 8, 0};
  __m128i b[11];
  // b[0] = *block128_as_m128i(block);
  memcpy(b, block, 16);
  for (size_t i = 1; i < 11; ++i) {
    __m128i b_p = b[i - 1];
    __m128i b_q = b[q_index[i - 1]];
    for (size_t m = u[q_index[i - 1]]; m; --m) {
      gf128sqr(&b_p, b_p);
    }
    gf128mul(&b[i], b_p, b_q);
  }
  gf128sqr(block, b[10]);
}
inline void block128_multiply_with_GF2_matrix(block128* block, const uint64_t* matrix) {
  block128 tmp;
  for (size_t j = 0; j < 2; j++) {
    uint64_t t = 0;
    for (size_t i = 0; i < 64; i++) {
      const uint64_t *A = &matrix[(j*64*2) + (i*2)];
      uint64_t bit = _mm_popcnt_u64((((uint64_t*)block)[0] & A[0]) ^ (((uint64_t*)block)[1] & A[1])) & 1;
      t ^= (bit << i);
    }
    ((uint64_t*)&tmp)[j] = t;
  }
  *block = tmp;
}
inline void block128_multiply_with_transposed_GF2_matrix(block128* block, const uint64_t* matrix) {
  const uint64_t *vptr = (uint64_t*)block;
  const __m256i *Ablock = (const __m256i*)matrix;

  __m256i cval[2] = {_mm256_setzero_si256(), _mm256_setzero_si256()};
  for (unsigned int w = 2; w; --w, ++vptr) {
    uint64_t idx = *vptr;
    for (unsigned int i = sizeof(uint64_t) * 8; i;
         i -= 8, idx >>= 8, Ablock += 4) {
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[0], mm256_compute_mask_2(idx, 0)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[1], mm256_compute_mask_2(idx, 2)));
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[2], mm256_compute_mask_2(idx, 4)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[3], mm256_compute_mask_2(idx, 6)));
    }
  }
  cval[0] = _mm256_xor_si256(cval[0], cval[1]);
  *block = _mm_xor_si128(_mm256_extracti128_si256(cval[0], 0),
                                     _mm256_extracti128_si256(cval[0], 1));
}


// ################### 192 ####################
inline __m128i* block192_as_m128i(block192* block) {
  return (__m128i*)block;
}
inline void clmul_schoolbook192(__m128i out[3], const __m128i a[2], const __m128i b[2]) {
  __m128i tmp[3];
  out[0] = _mm_clmulepi64_si128(a[0], b[0], 0x00);
  out[1] = _mm_clmulepi64_si128(a[0], b[0], 0x11);
  out[2] = _mm_clmulepi64_si128(a[1], b[1], 0x00);
  out[1] = _mm_xor_si128(out[1], _mm_clmulepi64_si128(a[0], b[1], 0x00));
  out[1] = _mm_xor_si128(out[1], _mm_clmulepi64_si128(a[1], b[0], 0x00));

  tmp[0] = _mm_clmulepi64_si128(a[0], b[0], 0x01);
  tmp[1] = _mm_clmulepi64_si128(a[0], b[0], 0x10);

  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[0] = _mm_xor_si128(out[0], tmp[1]);
  out[1] = _mm_xor_si128(out[1], tmp[2]);

  tmp[0] = _mm_clmulepi64_si128(a[1], b[0], 0x10);
  tmp[1] = _mm_clmulepi64_si128(a[0], b[1], 0x01);

  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[1] = _mm_xor_si128(out[1], tmp[1]);
  out[2] = _mm_xor_si128(out[2], tmp[2]);
}
inline void reduce_clmul192(__m128i out[2], const __m128i in[3]) {
  // modulus = x^192 + x^7 + x^2 + x + 1
  __m128i p = _mm_set_epi64x(0x0, 0x87);
  __m128i t0, t1, t2, t3;
  t0 = _mm_clmulepi64_si128(in[2], p, 0x01); // in[2]_high * p
  t3 = _mm_xor_si128(in[1], t0);             // update in[1]_low and in[1]_high

  t0 = _mm_clmulepi64_si128(in[2], p, 0x00); // in[2]_low * p
  t1 = _mm_slli_si128(t0, 8); // low 64bit of result, shifted to high
  t2 = _mm_srli_si128(t0, 8); // high 64bit of result, shifted to high
  t3 = _mm_xor_si128(t3, t2); // update in[1]_low

  t0 = _mm_clmulepi64_si128(t3, p, 0x01); // in[1]_high * p
  out[0] = _mm_xor_si128(t0, in[0]);
  out[0] = _mm_xor_si128(out[0], t1);
  out[1] = _mm_and_si128(t3, _mm_set_epi64x(0x0, 0xFFFFFFFFFFFFFFFF));
}
inline void sqr192(__m128i out[3], const __m128i a[2]) {
  __m128i tmp[2];
  __m128i sqrT = _mm_set_epi64x(0x5554515045444140, 0x1514111005040100);
  __m128i mask = _mm_set_epi64x(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F);
  tmp[0] = _mm_and_si128(a[0], mask);
  tmp[1] = _mm_srli_epi64(a[0], 4);
  tmp[1] = _mm_and_si128(tmp[1], mask);
  tmp[0] = _mm_shuffle_epi8(sqrT, tmp[0]);
  tmp[1] = _mm_shuffle_epi8(sqrT, tmp[1]);
  out[0] = _mm_unpacklo_epi8(tmp[0], tmp[1]);
  out[1] = _mm_unpackhi_epi8(tmp[0], tmp[1]);

  tmp[0] = _mm_and_si128(a[1], mask);
  tmp[1] = _mm_srli_epi64(a[1], 4);
  tmp[1] = _mm_and_si128(tmp[1], mask);
  tmp[0] = _mm_shuffle_epi8(sqrT, tmp[0]);
  tmp[1] = _mm_shuffle_epi8(sqrT, tmp[1]);
  out[2] = _mm_unpacklo_epi8(tmp[0], tmp[1]);
}
inline void gf192sqr(__m128i *out, const __m128i *in) {
  __m128i tmp[3];
  sqr192(tmp, in);
  reduce_clmul192(out, tmp);
}
inline void gf192mul(__m128i *out, const __m128i *in1, const __m128i *in2) {
  __m128i tmp[3];
  clmul_schoolbook192(tmp, in1, in2);
  reduce_clmul192(out, tmp);
}
inline void block192_inverse(block192* block) {
  const size_t u[12] = {1, 2, 3, 5, 10, 20, 23, 46, 92, 95, 190, 191};
  // q = u[i] - u[i - 1] should give us the corresponding values
  // (1, 1, 2, 5, 10, 3, 23, 46, 3, 95, 1), which will have corresponding
  // indexes
  const size_t q_index[11] = {0, 0, 1, 3, 4, 2, 6, 7, 2, 9, 0};
  __m128i b[12][2];

  memcpy(&b[0][0], &((uint64_t*)block)[0], 16);
  memcpy(&b[0][1], &((uint64_t*)block)[2], 8);

  for (size_t i = 1; i < 12; ++i) {

    __m128i b_p[2] = {b[i - 1][0], b[i - 1][1]};
    __m128i b_q[2] = {b[q_index[i - 1]][0], b[q_index[i - 1]][1]};

    for (size_t m = u[q_index[i - 1]]; m; --m) {
      gf192sqr(b_p, b_p);
    }
    gf192mul(b[i], b_p, b_q);
  }
  __m128i* tmp;
  tmp = (__m128i*)malloc(32); // offset problem..
  gf192sqr(tmp, b[11]);
  memcpy(block, tmp, 24);
  free(tmp);
}
inline void block192_multiply_with_GF2_matrix(block192* block, const uint64_t* matrix) {
  block192 tmp;
  for (size_t j = 0; j < 3; j++) {
    uint64_t t = 0;
    for (size_t i = 0; i < 64; i++) {
      const uint64_t *A = &matrix[(j*64*4) + (i*4)];
      uint64_t bit =
          _mm_popcnt_u64((((uint64_t*)block)[0] & A[0]) ^ (((uint64_t*)block)[1] & A[1]) ^
                         (((uint64_t*)block)[2] & A[2])) &  1;
      t ^= (bit << i);
    }
    ((uint64_t*)&tmp)[j] = t;
  }
  *block = tmp;
}
inline void block192_multiply_with_transposed_GF2_matrix(block192* block, const uint64_t* matrix) {
  const uint64_t *vptr = (uint64_t*)block;
  const __m256i *Ablock = (const __m256i*)matrix;

  __m256i cval[2] = {_mm256_setzero_si256(), _mm256_setzero_si256()};
  for (unsigned int w = 3; w; --w, ++vptr) {
    uint64_t idx = *vptr;
    for (unsigned int i = sizeof(uint64_t) * 8; i;
         i -= 4, idx >>= 4, Ablock += 4) {
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[0], mm256_compute_mask(idx, 0)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[1], mm256_compute_mask(idx, 1)));
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[2], mm256_compute_mask(idx, 2)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[3], mm256_compute_mask(idx, 3)));
    }
  }
  block256 tmp = _mm256_xor_si256(cval[0], cval[1]);
  memcpy(block, &tmp, 24);
}

// ################### 256 ####################
inline __m128i* block256_as_m128i(block256* block) {
  return (__m128i*)(block);
}
inline void clmul_schoolbook256(__m128i out[4], const __m128i a[2], const __m128i b[2]) {
  __m128i tmp[4];
  out[0] = _mm_clmulepi64_si128(a[0], b[0], 0x00);

  out[1] = _mm_clmulepi64_si128(a[0], b[0], 0x11);
  out[1] = _mm_xor_si128(out[1], _mm_clmulepi64_si128(a[0], b[1], 0x00));
  out[1] = _mm_xor_si128(out[1], _mm_clmulepi64_si128(a[1], b[0], 0x00));

  out[2] = _mm_clmulepi64_si128(a[1], b[1], 0x00);
  out[2] = _mm_xor_si128(out[2], _mm_clmulepi64_si128(a[0], b[1], 0x11));
  out[2] = _mm_xor_si128(out[2], _mm_clmulepi64_si128(a[1], b[0], 0x11));

  out[3] = _mm_clmulepi64_si128(a[1], b[1], 0x11);

  tmp[0] = _mm_clmulepi64_si128(a[0], b[0], 0x01);
  tmp[1] = _mm_clmulepi64_si128(a[0], b[0], 0x10);

  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[0] = _mm_xor_si128(out[0], tmp[1]);
  out[1] = _mm_xor_si128(out[1], tmp[2]);

  tmp[0] = _mm_clmulepi64_si128(a[1], b[0], 0x10);
  tmp[1] = _mm_clmulepi64_si128(a[0], b[1], 0x01);
  tmp[2] = _mm_clmulepi64_si128(a[0], b[1], 0x10);
  tmp[3] = _mm_clmulepi64_si128(a[1], b[0], 0x01);

  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[2] = _mm_xor_si128(tmp[2], tmp[3]);
  tmp[0] = _mm_xor_si128(tmp[0], tmp[2]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[1] = _mm_xor_si128(out[1], tmp[1]);
  out[2] = _mm_xor_si128(out[2], tmp[2]);

  tmp[0] = _mm_clmulepi64_si128(a[1], b[1], 0x01);
  tmp[1] = _mm_clmulepi64_si128(a[1], b[1], 0x10);

  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[2] = _mm_xor_si128(out[2], tmp[1]);
  out[3] = _mm_xor_si128(out[3], tmp[2]);
}
inline void reduce_clmul256(__m128i out[2], const __m128i in[4]) {
  // modulus = x^256 + x^10 + x^5 + x^2 + 1
  __m128i p = _mm_set_epi64x(0x0, 0x425);
  __m128i t0, t1, t2, t3;
  t0 = _mm_clmulepi64_si128(in[3], p, 0x01); // in[3]_high * p
  t1 = _mm_slli_si128(t0, 8);        // low 64bit of result, shifted to high
  t2 = _mm_srli_si128(t0, 8);        // high 64bit of result, shifted to low
  t3 = _mm_xor_si128(in[2], t2);     // update in[2]_low
  out[1] = _mm_xor_si128(in[1], t1); // update in[1]_hi

  t0 = _mm_clmulepi64_si128(in[3], p, 0x00); // in[3]_low * p
  out[1] = _mm_xor_si128(out[1], t0);        // update in[1]_hi and in[1]_lo

  t0 = _mm_clmulepi64_si128(in[2], p, 0x01); // in[2]_high * p
  t1 = _mm_slli_si128(t0, 8);         // low 64bit of result, shifted to high
  t2 = _mm_srli_si128(t0, 8);         // high 64bit of result, shifted to low
  out[1] = _mm_xor_si128(out[1], t2); // update in[1]_low
  out[0] = _mm_xor_si128(t1, in[0]);
  t0 = _mm_clmulepi64_si128(t3, p, 0x00); // in[2]_low * p
  out[0] = _mm_xor_si128(t0, out[0]);
}
inline void sqr256(__m128i out[4], const __m128i a[2]) {
  __m128i tmp[2];
  __m128i sqrT = _mm_set_epi64x(0x5554515045444140, 0x1514111005040100);
  __m128i mask = _mm_set_epi64x(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F);
  tmp[0] = _mm_and_si128(a[0], mask);
  tmp[1] = _mm_srli_epi64(a[0], 4);
  tmp[1] = _mm_and_si128(tmp[1], mask);
  tmp[0] = _mm_shuffle_epi8(sqrT, tmp[0]);
  tmp[1] = _mm_shuffle_epi8(sqrT, tmp[1]);
  out[0] = _mm_unpacklo_epi8(tmp[0], tmp[1]);
  out[1] = _mm_unpackhi_epi8(tmp[0], tmp[1]);

  tmp[0] = _mm_and_si128(a[1], mask);
  tmp[1] = _mm_srli_epi64(a[1], 4);
  tmp[1] = _mm_and_si128(tmp[1], mask);
  tmp[0] = _mm_shuffle_epi8(sqrT, tmp[0]);
  tmp[1] = _mm_shuffle_epi8(sqrT, tmp[1]);
  out[2] = _mm_unpacklo_epi8(tmp[0], tmp[1]);
  out[3] = _mm_unpackhi_epi8(tmp[0], tmp[1]);
}
inline void gf256sqr(__m128i *out, const __m128i *in) {
  __m128i tmp[4];
  sqr256(tmp, in);
  reduce_clmul256(out, tmp);
}
inline void gf256mul(__m128i *out, const __m128i *in1, const __m128i *in2) {
  __m128i tmp[4];
  clmul_schoolbook256(tmp, in1, in2);
  reduce_clmul256(out, tmp);
}
inline void block256_inverse(block256* block) {
  const size_t u[11] = {1, 2, 3, 6, 12, 15, 30, 60, 120, 240, 255};
  // q = u[i] - u[i - 1] should give us the corresponding values
  // (1, 1, 3, 6, 3, 15, 30, 60, 120, 15), which will have corresponding
  // indexes
  const size_t q_index[10] = {0, 0, 2, 3, 2, 5, 6, 7, 8, 5};
  __m128i b[11][2];

  memcpy(&b[0][0], &((uint64_t*)block)[0], 16);
  memcpy(&b[0][1], &((uint64_t*)block)[2], 16);

  for (size_t i = 1; i < 11; ++i) {

    __m128i b_p[2] = {b[i - 1][0], b[i - 1][1]};
    __m128i b_q[2] = {b[q_index[i - 1]][0], b[q_index[i - 1]][1]};

    for (size_t m = u[q_index[i - 1]]; m; --m) {
      gf256sqr(b_p, b_p);
    }

    gf256mul(b[i], b_p, b_q);
  }
  gf256sqr((__m128i*)block, b[10]);
}
inline void block256_multiply_with_GF2_matrix(block256* block, const uint64_t* matrix) {
  block256 tmp;
  for (size_t j = 0; j < 4; j++) {
    uint64_t t = 0;
    for (size_t i = 0; i < 64; i++) {
      const uint64_t *A = &matrix[(j*64*4) + (i*4)];
      uint64_t bit =
          _mm_popcnt_u64((((uint64_t*)block)[0] & A[0]) ^ (((uint64_t*)block)[1] & A[1]) ^
                         (((uint64_t*)block)[2] & A[2]) ^ (((uint64_t*)block)[3] & A[3])) &   1;
      t ^= (bit << i);
    }
    ((uint64_t*)&tmp)[j] = t;
  }
  *block = tmp;
}
inline void block256_multiply_with_transposed_GF2_matrix(block256* block, const uint64_t* matrix) {
  const uint64_t *vptr = (uint64_t*)block;
  const __m256i *Ablock = (const __m256i*)matrix;

  __m256i cval[2] = {_mm256_setzero_si256(), _mm256_setzero_si256()};
  for (unsigned int w = 4; w; --w, ++vptr) {
    uint64_t idx = *vptr;
    for (unsigned int i = sizeof(uint64_t) * 8; i;
         i -= 4, idx >>= 4, Ablock += 4) {
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[0], mm256_compute_mask(idx, 0)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[1], mm256_compute_mask(idx, 1)));
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[2], mm256_compute_mask(idx, 2)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[3], mm256_compute_mask(idx, 3)));
    }
  }
  block256 tmp = _mm256_xor_si256(cval[0], cval[1]);
  memcpy(block, &tmp, 24);
}


// ##################################################################################################################
// ################################### STOPS NOW ####################################################################
// ##################################################################################################################


inline block128 block128_xor(block128 x, block128 y) { return _mm_xor_si128(x, y); }
inline block256 block256_xor(block256 x, block256 y) { return _mm256_xor_si256(x, y); }
inline block128 block128_and(block128 x, block128 y) { return _mm_and_si128(x, y); }
inline block256 block256_and(block256 x, block256 y) { return _mm256_and_si256(x, y); }
inline block128 block128_set_zero() { return _mm_setzero_si128(); }
inline block256 block256_set_zero() { return _mm256_setzero_si256(); }
inline block128 block128_set_all_8(uint8_t x) { return _mm_set1_epi8(x); }
inline block256 block256_set_all_8(uint8_t x) { return _mm256_set1_epi8(x); }
inline block128 block128_set_low32(uint32_t x) { return _mm_setr_epi32(x, 0, 0, 0); }
inline block256 block256_set_low32(uint32_t x) { return _mm256_setr_epi32(x, 0, 0, 0, 0, 0, 0, 0); }
inline block128 block128_set_low64(uint64_t x) { return _mm_set_epi64x(0, x); }
inline block256 block256_set_low64(uint64_t x) { return _mm256_setr_epi64x(x, 0, 0, 0); }
inline block256 block256_set_128(block128 x0, block128 x1) { return _mm256_setr_m128i(x0, x1); }

inline block256 block256_set_low128(block128 x)
{
	return _mm256_inserti128_si256(_mm256_setzero_si256(), x, 0);
}

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

inline block384 block384_set_zero()
{
	block384 out;
	out.data[0] = block128_set_zero();
	out.data[1] = block128_set_zero();
	out.data[2] = block128_set_zero();
	return out;
}
inline block512 block512_set_zero()
{
	block512 out;
	out.data[0] = block256_set_zero();
	out.data[1] = block256_set_zero();
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

inline block384 block384_set_low32(uint32_t x)
{
	block384 out;
	out.data[0] = block128_set_low32(x);
	return out;
}
inline block512 block512_set_low32(uint32_t x)
{
	block512 out;
	out.data[0] = block256_set_low32(x);
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

inline bool block128_any_zeros(block128 x)
{
	return _mm_movemask_epi8(_mm_cmpeq_epi8(x, _mm_setzero_si128()));
}

inline bool block256_any_zeros(block256 x)
{
	return _mm256_movemask_epi8(_mm256_cmpeq_epi8(x, _mm256_setzero_si256()));
}

inline bool block192_any_zeros(block192 x)
{
	block256 b = block256_set_zero();
	memcpy(&b, &x, sizeof(x));
	return _mm256_movemask_epi8(_mm256_cmpeq_epi8(b, _mm256_setzero_si256())) & 0x00ffffff;
}

inline block128 block128_byte_reverse(block128 x)
{
	block128 shuffle = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
	return _mm_shuffle_epi8(x, shuffle);
}

inline block256 block256_from_2_block128(block128 x, block128 y)
{
	return _mm256_setr_m128i(x, y);
}

#define VOLE_BLOCK_SHIFT 0
typedef block128 vole_block;
inline vole_block vole_block_set_zero() { return block128_set_zero(); }
inline vole_block vole_block_xor(vole_block x, vole_block y) { return block128_xor(x, y); }
inline vole_block vole_block_and(vole_block x, vole_block y) { return block128_and(x, y); }
inline vole_block vole_block_set_all_8(uint8_t x) { return block128_set_all_8(x); }
inline vole_block vole_block_set_low32(uint32_t x) { return block128_set_low32(x); }
inline vole_block vole_block_set_low64(uint64_t x) { return block128_set_low64(x); }

#ifndef HAVE_VCLMUL
#define POLY_VEC_LEN_SHIFT 0
typedef block128 clmul_block;
inline clmul_block clmul_block_xor(clmul_block x, clmul_block y) { return block128_xor(x, y); }
inline clmul_block clmul_block_and(clmul_block x, clmul_block y) { return block128_and(x, y); }
inline clmul_block clmul_block_set_all_8(uint8_t x) { return block128_set_all_8(x); }
inline clmul_block clmul_block_set_zero() { return block128_set_zero(); }

inline clmul_block clmul_block_clmul_ll(clmul_block x, clmul_block y)
{
	return _mm_clmulepi64_si128(x, y, 0x00);
}
inline clmul_block clmul_block_clmul_lh(clmul_block x, clmul_block y)
{
	return _mm_clmulepi64_si128(x, y, 0x10);
}
inline clmul_block clmul_block_clmul_hl(clmul_block x, clmul_block y)
{
	return _mm_clmulepi64_si128(x, y, 0x01);
}
inline clmul_block clmul_block_clmul_hh(clmul_block x, clmul_block y)
{
	return _mm_clmulepi64_si128(x, y, 0x11);
}

inline clmul_block clmul_block_shift_left_64(clmul_block x)
{
	return _mm_slli_si128(x, 8);
}
inline clmul_block clmul_block_shift_right_64(clmul_block x)
{
	return _mm_srli_si128(x, 8);
}
inline clmul_block clmul_block_mix_64(clmul_block x, clmul_block y) // output = y high, x low.
{
	return _mm_alignr_epi8(x, y, 8);
}
inline clmul_block clmul_block_broadcast_low64(clmul_block x)
{
	return _mm_broadcastq_epi64(x);
}

#else
#define POLY_VEC_LEN_SHIFT 1
typedef block256 clmul_block;
inline clmul_block clmul_block_xor(clmul_block x, clmul_block y) { return block256_xor(x, y); }
inline clmul_block clmul_block_and(clmul_block x, clmul_block y) { return block256_and(x, y); }
inline clmul_block clmul_block_set_all_8(uint8_t x) { return block256_set_all_8(x); }
inline clmul_block clmul_block_set_zero() { return block256_set_zero(); }

inline clmul_block clmul_block_clmul_ll(clmul_block x, clmul_block y)
{
	return _mm256_clmulepi64_epi128(x, y, 0x00);
}
inline clmul_block clmul_block_clmul_lh(clmul_block x, clmul_block y)
{
	return _mm256_clmulepi64_epi128(x, y, 0x10);
}
inline clmul_block clmul_block_clmul_hl(clmul_block x, clmul_block y)
{
	return _mm256_clmulepi64_epi128(x, y, 0x01);
}
inline clmul_block clmul_block_clmul_hh(clmul_block x, clmul_block y)
{
	return _mm256_clmulepi64_epi128(x, y, 0x11);
}

inline clmul_block clmul_block_shift_left_64(clmul_block x)
{
	return _mm256_slli_si256(x, 8);
}
inline clmul_block clmul_block_shift_right_64(clmul_block x)
{
	return _mm256_srli_si256(x, 8);
}
inline clmul_block clmul_block_mix_64(clmul_block x, clmul_block y) // output = y high, x low.
{
	return _mm256_alignr_epi8(x, y, 8);
}
inline clmul_block clmul_block_broadcast_low64(clmul_block x)
{
	return _mm256_shuffle_epi32(x, 0x44);
}
#endif

#endif
