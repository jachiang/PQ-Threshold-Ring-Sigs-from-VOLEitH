#include "small_vole.h"
#include <string.h>
#include <stdbool.h>

#include "util.h"

#define COL_LEN VOLE_COL_BLOCKS

// TODO: probably can ditch most of the "restrict"s in inlined functions.

// Two different methods for efficiently reducing the PRG outputs to a single value:
//
// - Divide and conquer algorithm.
// - Straight-line method based on Gray's code. (TODO: figure out what paper I got this from.)
//
// This implementation combines these two methods. Divide and conquer is used at the lowest level,
// as it is inherently parallel and has a fixed access pattern when unrolled. Above it, the Gray's
// code method is used, as it needs very little temporary storage.

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

// Sender and receiver merged together, since they share most of the same code.
static ALWAYS_INLINE void vole(
	bool receiver, unsigned int k,
	const block_secpar* restrict keys, const prg_vole_fixed_key* restrict fixed_key,
	const vole_block* restrict u_or_c_in, vole_block* restrict vq, vole_block* restrict c_out,
	const uint8_t* restrict delta)
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
		// compiler will notice that it's unused and remove the corresponding code. TODO: just call
		// with size 1 smaller instead.
		prg_vole_key prgs[VOLE_WIDTH];
		prg_vole_iv ivs[VOLE_WIDTH];
		prg_vole_block raw_prg_output[VOLE_WIDTH * PRG_VOLE_BLOCKS];

		// TODO
		memset(&ivs, 0, sizeof(ivs));

		prg_vole_init(prgs, fixed_key, &keys[0], ivs, VOLE_WIDTH, PRG_VOLE_BLOCKS, 0, raw_prg_output);
		for (size_t j = 0; j < COL_LEN; ++j)
		{
			if (j)
				prg_vole_gen(prgs, fixed_key, VOLE_WIDTH, PRG_VOLE_BLOCKS, j * PRG_VOLE_BLOCKS, raw_prg_output);

			// TODO: How to convert from block128 to block256 without letting the compiler spill to
			// stack?
			// I think the issue is that this conversion is shared between prg_vole_init and
			// prg_vole_gen, so GCC thinks the input from both should be on the stack so that they
			// match. Need to duplicate instead.
			vole_block prg_output[VOLE_WIDTH];
			memcpy(prg_output, raw_prg_output, sizeof(prg_output));

			xor_reduce(prg_output);
			for (size_t col = 0; col < VOLE_WIDTH_SHIFT; ++col)
				vq[COL_LEN * col + j] = vole_block_xor(vq[COL_LEN * col + j], prg_output[col + 1]);

			// Ignore prg_output[0], as it's the only one that depends on keys[0], which is a dummy.
		}

		i = VOLE_WIDTH;
	}

	for (; i < (1 << k); i += VOLE_WIDTH)
	{
		prg_vole_key prgs[VOLE_WIDTH];
		prg_vole_iv ivs[VOLE_WIDTH];
		prg_vole_block raw_prg_output[VOLE_WIDTH * PRG_VOLE_BLOCKS];

		// TODO
		memset(&ivs, 0, sizeof(ivs));

		// Bitwise or is to make output_col be k - 1 when i + VOLE_WIDTH = 2**k, rather than k.
		unsigned int output_col = count_trailing_zeros((i + VOLE_WIDTH) | (1 << (k - 1)));

		prg_vole_init(prgs, fixed_key, &keys[i], ivs, VOLE_WIDTH, PRG_VOLE_BLOCKS, 0, raw_prg_output);
		for (size_t j = 0; j < COL_LEN; ++j)
		{
			if (j)
				prg_vole_gen(prgs, fixed_key, VOLE_WIDTH, PRG_VOLE_BLOCKS, j * PRG_VOLE_BLOCKS, raw_prg_output);

			vole_block prg_output[VOLE_WIDTH];
			memcpy(prg_output, raw_prg_output, sizeof(prg_output));

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

void vole_sender(
	unsigned int k, const block_secpar* restrict keys, const prg_vole_fixed_key* restrict fixed_key,
	const vole_block* restrict u, vole_block* restrict v, vole_block* restrict c)
{
	vole(false, k, keys, fixed_key, u, v, c, NULL);
}

void vole_receiver(
	unsigned int k, const block_secpar* restrict keys, const prg_vole_fixed_key* restrict fixed_key,
	const vole_block* restrict c, vole_block* restrict q,
	const uint8_t* restrict delta)
{
	vole(true, k, keys, fixed_key, c, q, NULL, delta);
}
