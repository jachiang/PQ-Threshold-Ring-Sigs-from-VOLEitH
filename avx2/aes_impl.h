#ifndef AES_IMPL_H
#define AES_IMPL_H

#include <immintrin.h>
#include <wmmintrin.h>

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

// For aes_keygen_ctr_vole:
//	block128 input[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
//	for (size_t l = 0; l < VOLE_WIDTH; ++l)
//		// TODO: should it start counting from a random value instead of 0?
//		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
//			input[l * VOLE_CIPHER_BLOCKS + m] = block128_set_low64(m);

// For aes_ctr_vole:
//	block_secpar input[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
//	for (size_t l = 0; l < VOLE_WIDTH; ++l)
//		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
//			input[l * VOLE_CIPHER_BLOCKS + m] =
//				block128_set_low64(counter * VOLE_CIPHER_BLOCKS + m);

// For aes_ctr_fixed_key_vole and rijndael256_ctr_fixed_key_vole: (really either block128 or
// block256)
//	block_secpar input[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
//	for (size_t l = 0; l < VOLE_WIDTH; ++l)
//		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
//			input[l * VOLE_CIPHER_BLOCKS + m] =
//				block_secpar_set_low64(counter * VOLE_CIPHER_BLOCKS + m);
//	for (size_t l = 0; l < VOLE_WIDTH; ++l)
//		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
//			input[l * VOLE_CIPHER_BLOCKS + m] =
//				block_secpar_xor(input[l * VOLE_CIPHER_BLOCKS + m], keys[l]);
//	rijndael_encrypt_fixed_key_vole(fixed_key, input, output);
//	for (size_t l = 0; l < VOLE_WIDTH; ++l)
//		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
//			output[l * VOLE_CIPHER_BLOCKS + m] =
//				block_secpar_xor(output[l * VOLE_CIPHER_BLOCKS + m], keys[l]);

// For other versions of above, either replace VOLE_WIDTH and VOLE_CIPHER_BLOCKS with
// AES_PREFERRED_WIDTH and 1, or with AES_PREFERRED_WIDTH/2 and 2.

#endif
