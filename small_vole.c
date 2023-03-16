#include "small_vole.h"
#include <string.h>
#include <stdbool.h>

#include "util.h"

#define COL_LEN (VOLE_ROWS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK)

// Two different methods for efficiently reducing the PRG outputs to a single value:
//
// - Divide and conquer algorithm.
// - Straight-line method based on Gray's codes. (TODO: figure out what paper I got this from.)
//
// This implementation combines these two methods. Divide and conquer is used at the lowest level,
// as it is inherently parallel and has a fixed access pattern when unrolled. Above it, the Gray's
// codes method is used, as it needs very little temporary storage.

// Output: v (or q) in in_out[1, ..., depth], and u in in_out[0].
static ALWAYS_INLINE void xor_reduce(vole_block* in_out)
{
	#ifdef __GNUC__
	#pragma GCC unroll (5)
	#endif
	for (size_t i = 0; i < VOLE_WIDTH_SHIFT; i++)
	{
		size_t stride = 1 << i;
		#ifdef __GNUC__
		#pragma GCC unroll (32)
		#endif
		for (size_t j = 0; j < VOLE_WIDTH; j += 2 * stride)
		{
			#ifdef __GNUC__
			#pragma GCC unroll (5)
			#endif
			for (size_t d = 0; d <= i; ++d)
				in_out[j + d] = vole_block_xor(in_out[j + d], in_out[j + d + stride]);
			in_out[j + i + 1] = in_out[j + stride];
		}
	}
}

// Returns true if output was generated along with the key
static ALWAYS_INLINE bool prg_keygen(
	vole_cipher_round_keys* round_keys, const block_secpar* restrict keys, vole_cipher_block* output)
{
#if defined(PRG_AES_CTR)
	vole_cipher_block input[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
	for (size_t l = 0; l < VOLE_WIDTH; ++l)
		// TODO: should it start counting from a random value instead of 0?
		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
			input[l * VOLE_CIPHER_BLOCKS + m] = vole_cipher_block_set_low64(m);
	aes_keygen_encrypt_vole(round_keys, keys, input, output);
	return true;
#else
	return false;
#endif
}

static ALWAYS_INLINE void prg_eval(
	size_t counter, const vole_cipher_round_keys* round_keys,
	const rijndael_round_keys* restrict fixed_key, const block_secpar* keys,
	vole_cipher_block* output)
{
	vole_cipher_block input[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
	for (size_t l = 0; l < VOLE_WIDTH; ++l)
		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
			input[l * VOLE_CIPHER_BLOCKS + m] =
				vole_cipher_block_set_low64(counter * VOLE_CIPHER_BLOCKS + m);

#if defined(PRG_AES_CTR)
	aes_encrypt_vole(round_keys, input, output);

#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
	for (size_t l = 0; l < VOLE_WIDTH; ++l)
		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
			input[l * VOLE_CIPHER_BLOCKS + m] =
				block_secpar_xor(input[l * VOLE_CIPHER_BLOCKS + m], keys[l]);
	rijndael_encrypt_fixed_key_vole(fixed_key, input, output);
	for (size_t l = 0; l < VOLE_WIDTH; ++l)
		for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
			output[l * VOLE_CIPHER_BLOCKS + m] =
				block_secpar_xor(output[l * VOLE_CIPHER_BLOCKS + m], keys[l]);
#endif
}

// Sender and receiver merged together, since they share most of the same code.
static ALWAYS_INLINE void generate_vole(
	bool receiver, unsigned int k,
	const block_secpar* restrict keys, const rijndael_round_keys* restrict fixed_key,
	const vole_block* restrict u_or_c_in, vole_block* restrict vq, vole_block* restrict c_out,
	const unsigned char* restrict delta)
{
	vole_block accum[COL_LEN];
	memset(&accum[0], 0, COL_LEN * sizeof(vole_block));

	if (receiver)
	{
		vole_block* q_ptr = vq;
		for (unsigned int col = 0; col < k; ++col)
			for (size_t j = 0; j < COL_LEN; ++j)
				*(q_ptr++) = vole_block_and(u_or_c_in[j], vole_block_set_all_8(delta[col]));
	}
	else
		memset(&vq[0], 0, COL_LEN * k * sizeof(vole_block));

	size_t i = 0;
	if (receiver)
	{
		// Handle first iteration separately, since the 0th PRG key is a dummy. Hopefully the
		// compiler will notice that it's unused and remove the corresponding code.
		vole_cipher_round_keys round_keys[VOLE_WIDTH];
		vole_cipher_block cipher_output[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
		size_t j = 0;

		if (prg_keygen(round_keys, &keys[0], cipher_output))
			goto have_cipher_output_i0;

		for (; j < COL_LEN; ++j)
		{
			prg_eval(j, round_keys, fixed_key, &keys[0], cipher_output);

have_cipher_output_i0:
			vole_block prg_output[VOLE_WIDTH];
			memcpy(prg_output, cipher_output, sizeof(prg_output));

			xor_reduce(prg_output);
			for (size_t col = 0; col < VOLE_WIDTH_SHIFT; ++col)
				vq[COL_LEN * col + j] = vole_block_xor(vq[COL_LEN * col + j], prg_output[col + 1]);

			// Ignore prg_output[0], as it's the only one that depends on keys[0], which is a dummy.
		}

		i = VOLE_WIDTH;
	}

	for (; i < (1 << k); i += VOLE_WIDTH)
	{
		vole_cipher_round_keys round_keys[VOLE_WIDTH];
		vole_cipher_block cipher_output[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
		size_t j = 0;

		size_t output_col = (i + VOLE_WIDTH >= (1 << k)) ? k - 1 : _tzcnt_u64(i + VOLE_WIDTH);

		if (prg_keygen(round_keys, &keys[i], cipher_output))
			goto have_cipher_output;

		for (; j < COL_LEN; ++j)
		{
			prg_eval(j, round_keys, fixed_key, &keys[i], cipher_output);

have_cipher_output:
			vole_block prg_output[VOLE_WIDTH];
			memcpy(prg_output, cipher_output, sizeof(prg_output));

			xor_reduce(prg_output);

			accum[j] = vole_block_xor(accum[j], prg_output[0]);
			for (size_t col = 0; col < VOLE_WIDTH_SHIFT; ++col)
				vq[COL_LEN * col + j] = vole_block_xor(vq[COL_LEN * col + j], prg_output[col + 1]);

			// Grey's codes method. output_col is the index of the bit that will change when
			// incrementing the Gray's code.
			vq[COL_LEN * output_col + j] = vole_block_xor(vq[COL_LEN * output_col + j], accum[j]);
		}
	}

	if (!receiver)
		for (size_t j = 0; j < COL_LEN; ++j)
			c_out[j] = vole_block_xor(u_or_c_in[j], accum[j]);
}

void generate_sender(
	unsigned int k, const block_secpar* restrict keys, const rijndael_round_keys* restrict fixed_key,
	const vole_block* restrict u, vole_block* restrict v, vole_block* restrict c)
{
	generate_vole(false, k, keys, fixed_key, u, v, c, NULL);
}

void generate_receiver(
	unsigned int k, const block_secpar* restrict keys, const rijndael_round_keys* restrict fixed_key,
	const vole_block* restrict c, vole_block* restrict q,
	const unsigned char* restrict delta)
{
	generate_vole(true, k, keys, fixed_key, c, q, NULL, delta);
}
