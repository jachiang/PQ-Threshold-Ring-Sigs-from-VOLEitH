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
	#pragma GCC unroll (16)
	#endif
	for (size_t i = 0; i < num_keys * evals_per_key; ++i)
		if (round == 0)
			state[i] = _mm_xor_si128(state[i], aeses[i / evals_per_key].keys[round]);
		else if (round < AES_ROUNDS)
			state[i] = _mm_aesenc_si128(state[i], aeses[i / evals_per_key].keys[round]);
		else
			state[i] = _mm_aesenclast_si128(state[i], aeses[i / evals_per_key].keys[round]);
}

// State for doing 4 AES key schedules at once.
typedef struct
{
	// These represent round keys for subsequent rounds, only with sbox outputs not yet XORed in.
	block128 key_slices[SECURITY_PARAM / 32];

	// Input to the next SBox.
	block128 next_sbox;
} aes_keygen_state;

ALWAYS_INLINE void cumulative_xor(block128* x, size_t n)
{
	for (size_t i = 0; i < n - 1; ++i)
		x[i + 1] = block128_xor(x[i], x[i + 1]);
}

// output_x[(i + 2) % 6] = input_x[i];
ALWAYS_INLINE void shift2_mod6(block128* x)
{
	block128 output[6];
	memcpy(output + 2, x, 4 * sizeof(block128));
	memcpy(output, x + 4, 2 * sizeof(block128));
	memcpy(x, output, 6 * sizeof(block128));
}

// output_x[(i + 4) % 8] = input_x[i];
ALWAYS_INLINE void shift4_mod8(block128* x)
{
	block128 output[8];
	memcpy(output + 4, x, 4 * sizeof(block128));
	memcpy(output, x + 4, 4 * sizeof(block128));
	memcpy(x, output, 8 * sizeof(block128));
}

// Requires that num_keys be a multiple of 4.
ALWAYS_INLINE void aes_keygen_init(
	aes_keygen_state* keygen_state, aes_round_keys* aeses, const block_secpar* keys, size_t num_keys)
{
	for (size_t i = 0; i < num_keys / 4; ++i, keys += 4, aeses += 4, ++keygen_state)
	{
		// Copy out the first round keys
		for (size_t j = 0; j < 4; ++j)
			memcpy(&aeses[j].keys[0], &keys[j], sizeof(block_secpar));

#if SECURITY_PARAM == 128
		transpose4x4_32(&keygen_state->key_slices[0], &keys[0]);

#elif SECURITY_PARAM == 192
		block128 low128s[4];
		for (size_t j = 0; j < 4; ++j)
			memcpy(&low128s[j], &keys[j], sizeof(block128));
		block128 hi64_01 = _mm_set_epi64x(keys[1].data[2], keys[0].data[2]);
		block128 hi64_23 = _mm_set_epi64x(keys[3].data[2], keys[2].data[2]);

		transpose4x4_32(&keygen_state->key_slices[0], &low128s[0]);
		transpose4x2_32(&keygen_state->key_slices[4], hi64_01, hi64_23);

#elif SECURITY_PARAM == 256
		block128 low128s[4];
		block128 hi128s[4];
		for (size_t j = 0; j < 4; ++j)
		{
			memcpy(&low128s[j], &keys[j], sizeof(block128));
			memcpy(&hi128s[j], ((const char*) &keys[j]) + sizeof(block128), sizeof(block128));
		}

		transpose4x4_32(&keygen_state->key_slices[0], &low128s[0]);
		transpose4x4_32(&keygen_state->key_slices[4], &hi128s[0]);
#endif

		keygen_state->next_sbox = keygen_state->key_slices[SECURITY_PARAM / 32 - 1];

		// Get ready for next rounds (starting with round 1 for 128 or 192 bit keys, or round 2 for
		// 256 bit keys).
		if (SECURITY_PARAM == 128)
			cumulative_xor(&keygen_state->key_slices[0], 4);
		else if (SECURITY_PARAM == 192)
		{
			shift2_mod6(&keygen_state->key_slices[0]);
			cumulative_xor(&keygen_state->key_slices[2], 4);
		}
		else
		{
			cumulative_xor(&keygen_state->key_slices[0], 4);
			cumulative_xor(&keygen_state->key_slices[4], 4);
		}
	}
}

ALWAYS_INLINE void aes_keygen_round(
	aes_keygen_state* keygen_state, aes_round_keys* aeses, size_t num_keys, int round)
{
	if (round < SECURITY_PARAM / 128) return;

	for (size_t i = 0; i < num_keys / 4; ++i, aeses += 4, ++keygen_state)
	{
		if (SECURITY_PARAM != 192 || round % 3 < 2)
		{
			// Undo ShiftRows operation, then apply RotWord.
			block128 inv_shift_rows =
				_mm_setr_epi8( 0, 13, 10,  7,  4,  1, 14, 11,  8,  5,  2, 15, 12,  9,  6,  3);
			block128 inv_shift_rows_then_rot_word =
				_mm_setr_epi8(13, 10,  7,  0,  1, 14, 11,  4,  5,  2, 15,  8,  9,  6,  3, 12);

			block128 perm, round_constant;
			if (SECURITY_PARAM == 256 && round % 2 == 1)
			{
				perm = inv_shift_rows;
				round_constant = _mm_setzero_si128();
			}
			else
			{
				perm = inv_shift_rows_then_rot_word;
				int idx = (2 * round + 1) / (SECURITY_PARAM / 64);
				round_constant = _mm_set1_epi32(aes_round_constants[idx - 1]);
			}

			block128 sbox_out = _mm_aesenclast_si128(
				_mm_shuffle_epi8(keygen_state->next_sbox, perm), round_constant);

			size_t range_start = (SECURITY_PARAM == 192 && round % 3 == 1) ? 2 : 0;
			size_t range_end = (SECURITY_PARAM == 192) ? 6 : 4;
			for (size_t j = range_start; j < range_end; ++j)
				keygen_state->key_slices[j] = block128_xor(keygen_state->key_slices[j], sbox_out);
		}

		if (SECURITY_PARAM != 192 || round % 3 == 2)
			keygen_state->next_sbox = keygen_state->key_slices[3];
		else if (round % 3 == 0)
			keygen_state->next_sbox = keygen_state->key_slices[5];

		// Unslice the current 4 keys slices to get this round's keys.
		block128 round_keys[4];
		transpose4x4_32(round_keys, &keygen_state->key_slices[0]);
		for (size_t j = 0; j < 4; ++j)
			aeses[j].keys[round] = round_keys[j];

		// Update round keys slices for next round.
		if (SECURITY_PARAM == 192)
		{
			shift2_mod6(&keygen_state->key_slices[0]);
			size_t next_sbox_idx = (round % 3 + 1) * 2;
			cumulative_xor(&keygen_state->key_slices[1], next_sbox_idx - 1);
			cumulative_xor(&keygen_state->key_slices[next_sbox_idx], 6 - next_sbox_idx);
		}
		else
		{
			cumulative_xor(&keygen_state->key_slices[0], 4);
			if (SECURITY_PARAM == 256)
				shift4_mod8(&keygen_state->key_slices[0]);
		}
	}
}

// TODO: should we start counting from a random value instead of 0?
// TODO: I think this can go into a .c file. It's already doing lots of memory writes to the round
// keys, so it's not much more to have the output also go to the stack.
inline void aes_keygen_ctr_x2(aes_round_keys* aeses, const block_secpar* keys, size_t counter, block128* output)
{
	block128 state[AES_PREFERRED_WIDTH];
	for (size_t l = 0; l < AES_PREFERRED_WIDTH / 2; ++l)
		for (size_t m = 0; m < 2; ++m)
			state[l * 2 + m] = block128_set_low64(counter + m);

	aes_keygen_state keygen_state[AES_PREFERRED_WIDTH / 8];
	aes_keygen_init(keygen_state, aeses, keys, AES_PREFERRED_WIDTH / 2);

#if SECURITY_PARAM == 128
	size_t round_start = 1;
	size_t round_end = AES_ROUNDS - 1;
	size_t unroll_rounds = 1;
#elif SECURITY_PARAM == 192
	size_t round_start = 1;
	size_t round_end = AES_ROUNDS - 1;
	size_t unroll_rounds = 3;
#elif SECURITY_PARAM == 256
	size_t round_start = 2;
	size_t round_end = AES_ROUNDS - 2;
	size_t unroll_rounds = 2;
#endif

	// Separate out the first and last rounds, as they work differently.
	aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, 0);
	if (round_start > 1)
		aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, 1);

	for (int round = round_start; round <= round_end; round += unroll_rounds)
	{
		// Unroll the loop, as the key generation follows a pattern that repeats every unroll_rounds
		// iterations.

		aes_keygen_round(keygen_state, aeses, AES_PREFERRED_WIDTH / 2, round);
		aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, round);
		if (unroll_rounds > 1)
		{
			if (round_end < round + 1)
				break;
			aes_keygen_round(keygen_state, aeses, AES_PREFERRED_WIDTH / 2, round + 1);
			aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, round + 1);
		}
		if (unroll_rounds > 2)
		{
			if (round_end < round + 2)
				break;
			aes_keygen_round(keygen_state, aeses, AES_PREFERRED_WIDTH / 2, round + 2);
			aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, round + 2);
		}
	}

	aes_keygen_round(keygen_state, aeses, AES_PREFERRED_WIDTH / 2, round_end + 1);
	aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, round_end + 1);
	if (round_end + 2 <= AES_ROUNDS)
	{
		aes_keygen_round(keygen_state, aeses, AES_PREFERRED_WIDTH / 2, round_end + 2);
		aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, round_end + 2);
	}

	memcpy(output, state, AES_PREFERRED_WIDTH * sizeof(block128));
}

inline void aes_keygen_ctr_vole(aes_round_keys* aeses, const block_secpar* keys, size_t counter, block128* output)
{
	// If PRG_AES_CTR is undefined then this function is never used.
#ifdef PRG_AES_CTR
	static_assert(VOLE_WIDTH == AES_PREFERRED_WIDTH / 2);
	static_assert(VOLE_CIPHER_BLOCKS == 2);
	aes_keygen_ctr_x2(aeses, keys, counter, output);
#endif
}

inline void aes_ctr_x2(const aes_round_keys* aeses, size_t counter, block128* output)
{
	block128 state[AES_PREFERRED_WIDTH];
	for (size_t l = 0; l < AES_PREFERRED_WIDTH / 2; ++l)
		for (size_t m = 0; m < 2; ++m)
			state[l * 2 + m] = block128_set_low64(counter + m);

	// Make it easier for the compiler to optimize by unwinding the first and last rounds. (Since we
	// aren't asking it to unwind the whole loop.)
	aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, 0);
	for (int round = 1; round < AES_ROUNDS; ++round)
		aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, round);
	aes_round(aeses, state, AES_PREFERRED_WIDTH / 2, 2, AES_ROUNDS);

	memcpy(output, state, AES_PREFERRED_WIDTH * sizeof(block128));
}

inline void aes_ctr_x1(const aes_round_keys* aeses, size_t counter, block128* output)
{
	block128 state[AES_PREFERRED_WIDTH];
	for (size_t l = 0; l < AES_PREFERRED_WIDTH; ++l)
		state[l] = block128_set_low64(counter);

	aes_round(aeses, state, AES_PREFERRED_WIDTH, 1, 0);
	for (int round = 1; round < AES_ROUNDS; ++round)
		aes_round(aeses, state, AES_PREFERRED_WIDTH, 1, round);
	aes_round(aeses, state, AES_PREFERRED_WIDTH, 1, AES_ROUNDS);

	memcpy(output, state, AES_PREFERRED_WIDTH * sizeof(block128));
}

inline void aes_ctr_vole(const aes_round_keys* aeses, size_t counter, block128* output)
{
	// If PRG_AES_CTR is undefined then this function is never used.
#ifdef PRG_AES_CTR
	static_assert(VOLE_WIDTH == AES_PREFERRED_WIDTH / 2);
	static_assert(VOLE_CIPHER_BLOCKS == 2);
	aes_ctr_x2(aeses, counter, output);
#endif
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

// For other versions of above, either replace VOLE_WIDTH and VOLE_CIPHER_BLOCKS with
// AES_PREFERRED_WIDTH and 1, or with AES_PREFERRED_WIDTH/2 and 2.

#endif
