#ifndef AES_IMPL_H
#define AES_IMPL_H

#include <string.h>
#include <inttypes.h>
#include <immintrin.h>
#include <wmmintrin.h>

#include "transpose.h"
#include "util.h"

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
	block128 input = *state;
	block128 state_after_sbox = _mm_aesenclast_si128(input, _mm_setzero_si128());
	*after_sbox = state_after_sbox;

	if (round < AES_ROUNDS)
		*state = _mm_aesenc_si128(input, aes->keys[round]);
	else
		*state = _mm_xor_si128(state_after_sbox, aes->keys[round]);
}

ALWAYS_INLINE void aes_round(
	const aes_round_keys* aeses, block128* state, size_t num_keys, size_t evals_per_key, int round)
{
	#ifdef __GNUC__
	_Pragma(STRINGIZE(GCC unroll (2*AES_PREFERRED_WIDTH)))
	#endif
	for (size_t i = 0; i < num_keys * evals_per_key; ++i)
		if (round == 0)
			state[i] = _mm_xor_si128(state[i], aeses[i / evals_per_key].keys[round]);
		else if (round < AES_ROUNDS)
			state[i] = _mm_aesenc_si128(state[i], aeses[i / evals_per_key].keys[round]);
		else
			state[i] = _mm_aesenclast_si128(state[i], aeses[i / evals_per_key].keys[round]);
}

ALWAYS_INLINE void aes_keygen_ctr(
	aes_round_keys* restrict aeses, const block_secpar* restrict keys, const block128* restrict ivs,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block128* restrict output)
{
	assert(num_keys <= 2 * AES_PREFERRED_WIDTH);
	assert(1 <= num_blocks && num_blocks <= 4);

	// Use a switch to select which function. The case should always be resolved at compile time.
	static_assert(AES_PREFERRED_WIDTH <= 16);
	switch(num_keys * 4 + num_blocks)
	{
#define AES_KEYGEN_SWITCH_CASE_KB(num_keys,num_blocks) \
	case (num_keys * 4 + num_blocks): \
	{ \
		void aes_keygen_impl_##num_keys##_##num_blocks( \
			aes_round_keys*, const block_secpar*, const block128*, uint32_t, block128*); \
		aes_keygen_impl_##num_keys##_##num_blocks(aeses, keys, ivs, counter, output); \
		break; \
	}
#define AES_KEYGEN_SWITCH_CASE_K(num_keys) \
		AES_KEYGEN_SWITCH_CASE_KB(num_keys, 1) \
		AES_KEYGEN_SWITCH_CASE_KB(num_keys, 2) \
		AES_KEYGEN_SWITCH_CASE_KB(num_keys, 3) \
		AES_KEYGEN_SWITCH_CASE_KB(num_keys, 4)

		AES_KEYGEN_SWITCH_CASE_K(1)
		AES_KEYGEN_SWITCH_CASE_K(2)
		AES_KEYGEN_SWITCH_CASE_K(3)
		AES_KEYGEN_SWITCH_CASE_K(4)
		AES_KEYGEN_SWITCH_CASE_K(5)
		AES_KEYGEN_SWITCH_CASE_K(6)
		AES_KEYGEN_SWITCH_CASE_K(7)
		AES_KEYGEN_SWITCH_CASE_K(8)
		AES_KEYGEN_SWITCH_CASE_K(9)
		AES_KEYGEN_SWITCH_CASE_K(10)
		AES_KEYGEN_SWITCH_CASE_K(11)
		AES_KEYGEN_SWITCH_CASE_K(12)
		AES_KEYGEN_SWITCH_CASE_K(13)
		AES_KEYGEN_SWITCH_CASE_K(14)
		AES_KEYGEN_SWITCH_CASE_K(15)
		AES_KEYGEN_SWITCH_CASE_K(16)
		AES_KEYGEN_SWITCH_CASE_K(17)
		AES_KEYGEN_SWITCH_CASE_K(18)
		AES_KEYGEN_SWITCH_CASE_K(19)
		AES_KEYGEN_SWITCH_CASE_K(20)
		AES_KEYGEN_SWITCH_CASE_K(21)
		AES_KEYGEN_SWITCH_CASE_K(22)
		AES_KEYGEN_SWITCH_CASE_K(23)
		AES_KEYGEN_SWITCH_CASE_K(24)
		AES_KEYGEN_SWITCH_CASE_K(25)
		AES_KEYGEN_SWITCH_CASE_K(26)
		AES_KEYGEN_SWITCH_CASE_K(27)
		AES_KEYGEN_SWITCH_CASE_K(28)
		AES_KEYGEN_SWITCH_CASE_K(29)
		AES_KEYGEN_SWITCH_CASE_K(30)
		AES_KEYGEN_SWITCH_CASE_K(31)
		AES_KEYGEN_SWITCH_CASE_K(32)
#undef AES_KEYGEN_SWITCH_CASE_K
#undef AES_KEYGEN_SWITCH_CASE_KB
	}
}

inline void aes_ctr(
	const aes_round_keys* restrict aeses,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block128* restrict output)
{
	// Upper bound just to avoid VLAs.
	assert(num_keys * num_blocks <= 8 * AES_PREFERRED_WIDTH);
	block128 state[8 * AES_PREFERRED_WIDTH];
	for (size_t l = 0; l < num_keys; ++l)
		for (size_t m = 0; m < num_blocks; ++m)
			state[l * num_blocks + m] = block128_set_low64(counter + m);

	// Make it easier for the compiler to optimize by unwinding the first and last rounds. (Since we
	// aren't asking it to unwind the whole loop.)
	aes_round(aeses, state, num_keys, num_blocks, 0);
	for (int round = 1; round < AES_ROUNDS; ++round)
		aes_round(aeses, state, num_keys, num_blocks, round);
	aes_round(aeses, state, num_keys, num_blocks, AES_ROUNDS);

	memcpy(output, state, num_keys * num_blocks * sizeof(block128));
}

// For aes_ctr_fixed_key_vole and rijndael256_ctr_fixed_key_vole: (really either block128 or
// block256)
//	block_secpar input[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
//	for (size_t l = 0; l < VOLE_WIDTH; ++l)
//		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
//			input[l * VOLE_CIPHER_BLOCKS + m] = block_secpar_set_low64(counter + m);
//	for (size_t l = 0; l < VOLE_WIDTH; ++l)
//		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
//			input[l * VOLE_CIPHER_BLOCKS + m] =
//				block_secpar_xor(input[l * VOLE_CIPHER_BLOCKS + m], keys[l]);
//	rijndael_encrypt_fixed_key_vole(fixed_key, input, output);
//	for (size_t l = 0; l < VOLE_WIDTH; ++l)
//		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
//			output[l * VOLE_CIPHER_BLOCKS + m] =
//				block_secpar_xor(output[l * VOLE_CIPHER_BLOCKS + m], keys[l]);

#endif
