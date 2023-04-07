#include "aes.h"

#define KEYGEN_WIDTH 4

// State for doing KEYGEN_WIDTH AES key schedules at once.
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

// Starts the key schedule on KEYGEN_WIDTH * num_keygen_states keys.
ALWAYS_INLINE void aes_keygen_init(
	aes_keygen_state* keygen_state, aes_round_keys* aeses,
	const block_secpar* keys, size_t num_keygen_states)
{
	for (size_t i = 0; i < num_keygen_states;
	     ++i, keys += KEYGEN_WIDTH, aeses += KEYGEN_WIDTH, ++keygen_state)
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
	aes_keygen_state* keygen_state, aes_round_keys* aeses, size_t num_keygen_states, int round)
{
	if (round < SECURITY_PARAM / 128) return;

	for (size_t i = 0; i < num_keygen_states; ++i, aeses += 4, ++keygen_state)
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

ALWAYS_INLINE void aes_keygen_impl(
	aes_round_keys* aeses_out, const block_secpar* keys, const block128* ivs,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block128* output)
{
	// Upper bound just to avoid VLAs.
	block128 state[8 * AES_PREFERRED_WIDTH];
	for (size_t l = 0; l < num_keys; ++l)
		for (size_t m = 0; m < num_blocks; ++m)
			state[l * num_blocks + m] = block128_set_low64(counter + m);

	size_t num_keygen_states = (num_keys + KEYGEN_WIDTH - 1) / KEYGEN_WIDTH;
	aes_keygen_state keygen_states[2 * AES_PREFERRED_WIDTH / KEYGEN_WIDTH];

	// Don't access out of bounds if num_keys is not a multiple of KEYGEN_WIDTH.
	block_secpar keys_copied[2 * AES_PREFERRED_WIDTH];
	aes_round_keys aeses_to_copy[2 * AES_PREFERRED_WIDTH];
	aes_round_keys* aeses = aeses_out;
	if (num_keys % KEYGEN_WIDTH)
	{
		memcpy(&keys_copied[0], keys, num_keys * sizeof(block_secpar));
		memset(&keys_copied[num_keys], 0, (num_keygen_states * KEYGEN_WIDTH - num_keys) * sizeof(block_secpar));
		keys = &keys_copied[0];
		aeses = &aeses_to_copy[0];
	}

	aes_keygen_state keygen_state[2 * AES_PREFERRED_WIDTH / KEYGEN_WIDTH];
	aes_keygen_init(keygen_state, aeses, keys, num_keygen_states);

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
	aes_round(aeses, state, num_keys, num_blocks, 0);
	if (round_start > 1)
		aes_round(aeses, state, num_keys, num_blocks, 1);

	// Bake the ivs into the round keys.
	for (size_t i = 0; i < num_keys; ++i)
		aeses[i].keys[0] = block128_xor(aeses[i].keys[0], ivs[i]);

	for (int round = round_start; round <= round_end; round += unroll_rounds)
	{
		// Unroll the loop, as the key generation follows a pattern that repeats every unroll_rounds
		// iterations.

		aes_keygen_round(keygen_state, aeses, num_keygen_states, round);
		aes_round(aeses, state, num_keys, num_blocks, round);
		if (unroll_rounds > 1)
		{
			if (round_end < round + 1)
				break;
			aes_keygen_round(keygen_state, aeses, num_keygen_states, round + 1);
			aes_round(aeses, state, num_keys, num_blocks, round + 1);
		}
		if (unroll_rounds > 2)
		{
			if (round_end < round + 2)
				break;
			aes_keygen_round(keygen_state, aeses, num_keygen_states, round + 2);
			aes_round(aeses, state, num_keys, num_blocks, round + 2);
		}
	}

	aes_keygen_round(keygen_state, aeses, num_keygen_states, round_end + 1);
	aes_round(aeses, state, num_keys, num_blocks, round_end + 1);
	if (round_end + 2 <= AES_ROUNDS)
	{
		aes_keygen_round(keygen_state, aeses, num_keygen_states, round_end + 2);
		aes_round(aeses, state, num_keys, num_blocks, round_end + 2);
	}

	memcpy(output, state, num_keys * num_blocks * sizeof(block128));
	if (num_keys % KEYGEN_WIDTH)
		memcpy(aeses_out, aeses, num_keys * sizeof(aes_round_keys));
}

// Allow num_keys and num_blocks to be hardcoded by the compiler.
#define DEF_AES_KEYGEN_IMPL_KB(num_keys,num_blocks) \
	void aes_keygen_impl_##num_keys##_##num_blocks( \
		aes_round_keys* restrict aeses, const block_secpar* restrict keys, \
		const block128* restrict ivs, uint32_t counter, block128* restrict output) \
	{ \
		if (num_keys <= 2 * AES_PREFERRED_WIDTH && num_blocks <= 4) \
			aes_keygen_impl(aeses, keys, ivs, num_keys, num_blocks, counter, output); \
	}
#define DEF_AES_KEYGEN_IMPL_K(num_keys) \
	DEF_AES_KEYGEN_IMPL_KB(num_keys, 1) \
	DEF_AES_KEYGEN_IMPL_KB(num_keys, 2) \
	DEF_AES_KEYGEN_IMPL_KB(num_keys, 3) \
	DEF_AES_KEYGEN_IMPL_KB(num_keys, 4)

// These are mostly unused, but it's easier to list them all than to keep track of all of the ones
// that are used.
static_assert(AES_PREFERRED_WIDTH <= 16);
DEF_AES_KEYGEN_IMPL_K(1)
DEF_AES_KEYGEN_IMPL_K(2)
DEF_AES_KEYGEN_IMPL_K(3)
DEF_AES_KEYGEN_IMPL_K(4)
DEF_AES_KEYGEN_IMPL_K(5)
DEF_AES_KEYGEN_IMPL_K(6)
DEF_AES_KEYGEN_IMPL_K(7)
DEF_AES_KEYGEN_IMPL_K(8)
DEF_AES_KEYGEN_IMPL_K(9)
DEF_AES_KEYGEN_IMPL_K(10)
DEF_AES_KEYGEN_IMPL_K(11)
DEF_AES_KEYGEN_IMPL_K(12)
DEF_AES_KEYGEN_IMPL_K(13)
DEF_AES_KEYGEN_IMPL_K(14)
DEF_AES_KEYGEN_IMPL_K(15)
DEF_AES_KEYGEN_IMPL_K(16)
DEF_AES_KEYGEN_IMPL_K(17)
DEF_AES_KEYGEN_IMPL_K(18)
DEF_AES_KEYGEN_IMPL_K(19)
DEF_AES_KEYGEN_IMPL_K(20)
DEF_AES_KEYGEN_IMPL_K(21)
DEF_AES_KEYGEN_IMPL_K(22)
DEF_AES_KEYGEN_IMPL_K(23)
DEF_AES_KEYGEN_IMPL_K(24)
DEF_AES_KEYGEN_IMPL_K(25)
DEF_AES_KEYGEN_IMPL_K(26)
DEF_AES_KEYGEN_IMPL_K(27)
DEF_AES_KEYGEN_IMPL_K(28)
DEF_AES_KEYGEN_IMPL_K(29)
DEF_AES_KEYGEN_IMPL_K(30)
DEF_AES_KEYGEN_IMPL_K(31)
DEF_AES_KEYGEN_IMPL_K(32)

void aes_keygen(aes_round_keys* aes, block_secpar key)
{
	// There are more efficient ways to run the key schedule on a single key, but this function
	// isn't used much anyway.
	block128 iv = block128_set_zero();
	block128 empty_output;
	aes_keygen_impl(aes, &key, &iv, 1, 0, 0, &empty_output);
}
