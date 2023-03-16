#ifndef BLOCK_IMPL_H
#define BLOCK_IMPL_H

#include <immintrin.h>

typedef __m128i block128;
typedef __m256i block256;

inline block128 block128_xor(block128 x, block128 y) { return _mm_xor_si128(x, y); }
inline block256 block256_xor(block256 x, block256 y) { return _mm256_xor_si256(x, y); }
inline block128 block128_and(block128 x, block128 y) { return _mm_and_si128(x, y); }
inline block256 block256_and(block256 x, block256 y) { return _mm256_and_si256(x, y); }
inline block128 block128_set_all_8(uint8_t x) { return _mm_set1_epi8(x); }
inline block256 block256_set_all_8(uint8_t x) { return _mm256_set1_epi8(x); }
inline block128 block128_set_low64(uint64_t x) { return _mm_set_epi64x(0, x); }
inline block256 block256_set_low64(uint64_t x) { return _mm256_setr_epi64x(x, 0, 0, 0); }
inline block256 block256_set_128(block128 x0, block128 x1) { return _mm256_setr_m128i(x0, x1); }

#if SECURITY_PARAM == 128
typedef block128 block_secpar;
inline block_secpar block_secpar_xor(block_secpar x, block_secpar y) { return block128_xor(x, y); }
inline block_secpar block_secpar_and(block_secpar x, block_secpar y) { return block128_and(x, y); }
inline block_secpar block_secpar_set_low64(uint64_t x) { return block128_set_low64(x); }
#elif SECURITY_PARAM == 192
typedef block192 block_secpar;
inline block_secpar block_secpar_xor(block_secpar x, block_secpar y) { return block192_xor(x, y); }
inline block_secpar block_secpar_and(block_secpar x, block_secpar y) { return block192_and(x, y); }
inline block_secpar block_secpar_set_low64(uint64_t x) { return block192_set_low64(x); }
#elif SECURITY_PARAM == 256
typedef block256 block_secpar;
inline block_secpar block_secpar_xor(block_secpar x, block_secpar y) { return block256_xor(x, y); }
inline block_secpar block_secpar_and(block_secpar x, block_secpar y) { return block256_and(x, y); }
inline block_secpar block_secpar_set_low64(uint64_t x) { return block256_set_low64(x); }
#endif

#define VOLE_BLOCK_SHIFT 1
typedef block256 vole_block;
inline vole_block vole_block_xor(vole_block x, vole_block y) { return block256_xor(x, y); }
inline vole_block vole_block_and(vole_block x, vole_block y) { return block256_and(x, y); }
inline vole_block vole_block_set_all_8(uint8_t x) { return block256_set_all_8(x); }
inline vole_block vole_block_set_low64(uint64_t x) { return block256_set_low64(x); }

#endif
