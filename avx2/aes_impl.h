#ifndef AES_IMPL_H
#define AES_IMPL_H

#include <immintrin.h>
#include <wmmintrin.h>

#define AES_VECTOR_WIDTH_SHIFT 0
#define AES_PREFERRED_WIDTH_SHIFT 3
#define RIJNDAEL256_PREFERRED_WIDTH_SHIFT 2

typedef struct
{
	block128 keys[AES_ROUNDS + 1];
} aes_round_keys;

typedef struct
{
	block192 keys[RIJNDAEL192_ROUNDS + 1];
} rijndael192_round_keys;

typedef struct
{
	block256 keys[RIJNDAEL256_ROUNDS + 1];
} rijndael256_round_keys;

inline void aes_round_function(const aes_round_keys* aes, block128* state, block128* after_sbox, int round)
{
	__m128i input = *state;
	__m128i state_after_sbox = _mm_aesenclast_si128(input, _mm_setzero_si128());
	*after_sbox = state_after_sbox;

	if (round < AES_ROUNDS)
		*state = _mm_aesenc_si128(input, aes->keys[round]);
	else
		*state = _mm_xor_si128(state_after_sbox, aes->keys[round]);
}

#endif
