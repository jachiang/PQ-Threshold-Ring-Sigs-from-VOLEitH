#include "config.h"
#include "small_vole.h"

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
static inline void xor_reduce(vole_block* in_out)
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
			for (size_t k = 0; k <= i; ++k)
				in_out[j + k] = vole_block_xor(in_out[j + k], in_out[j + k + stride]);
			in_out[j + i + 1] = in_out[j + stride];
		}
	}
}

void generate_sender_min_k(
	const block_secpar* restrict keys, const rijndael_round_keys* restrict fixed_key,
	const vole_block* restrict u, vole_block* restrict v, vole_block* restrict c)
{
	vole_block accum[COL_LEN];
	memset(&accum[0], 0, COL_LEN * sizeof(vole_block));
	memset(&v[0], 0, COL_LEN * VOLE_MIN_K * sizeof(vole_block));

	for (size_t i = 0; i < (1 << VOLE_MIN_K); i += VOLE_WIDTH)
	{
		cipher_round_keys round_keys[VOLE_WIDTH];
		vole_cipher_block cipher_output[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
		size_t j = 0;

#if defined(PRG_AES_CTR)
		aes_keygen_encrypt_vole(round_keys, &keys[i], cipher_output);
		goto have_cipher_output;
#endif

		for (; j < COL_LEN; ++j)
		{
			vole_cipher_block cipher_input[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
			vole_cipher_block cipher_output[VOLE_WIDTH * VOLE_CIPHER_BLOCKS];
			for (size_t l = 0; l < VOLE_WIDTH; ++l)
				// TODO: should it start counting from a random value instead of 0?
				for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
					cipher_input[l * VOLE_CIPHER_BLOCKS + m] =
						vole_cipher_block_set_low64(j*VOLE_CIPHER_BLOCKS + m);

#if defined(PRG_AES_CTR)
			aes_encrypt_vole(round_keys, cipher_input, cipher_output);
#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
			for (size_t l = 0; l < VOLE_WIDTH; ++l)
				for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
					cipher_input[l * VOLE_CIPHER_BLOCKS + m] =
						block_secpar_xor(cipher_input[l * VOLE_CIPHER_BLOCKS + m], keys[i + l]);
			rijndael_encrypt_fixed_key_vole(fixed_key, cipher_input, cipher_output);
			for (size_t l = 0; l < VOLE_WIDTH; ++l)
				for (size_t m = 0; m < VOLE_CIPHER_BLOCKS; ++m)
					cipher_output[l * VOLE_CIPHER_BLOCKS + m] =
						block_secpar_xor(cipher_output[l * VOLE_CIPHER_BLOCKS + m], keys[i + l]);
#endif

have_cipher_output:
			vole_block prg_output[VOLE_WIDTH];
			memcpy(prg_output, cipher_output, sizeof(prg_output));

			xor_reduce(prg_output);

			accum[j] = vole_block_xor(accum[j], prg_output[0]);
			for (size_t col = 0; col < VOLE_WIDTH_SHIFT; ++col)
				v[COL_LEN * col + j] = vole_block_xor(v[COL_LEN * col + j], prg_output[col + 1]);

			// Grey's codes trick. col is the index of the bit that will change when incrementing
			// the Gray's code.
			size_t col = _mm_tzcnt_u64(i + VOLE_WIDTH);
			if (col > VOLE_MIN_K - 1)
				col = VOLE_MIN_K - 1;
			v[COL_LEN * col + j] = vole_block_xor(v[COL_LEN * col + j], accum[j]);
		}
	}

	for (size_t j = 0; j < COL_LEN; ++j)
		c[j] = vole_block_xor(u[j], accum[j]);
}
