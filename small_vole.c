#include "config.h"
#include "small_vole.h"

// TODO: Should use a different order from SSOT. Compute key schedules for a group of seeds,
// generate all output and XORs for those whole columns, then move on to the next.


// Output: v (or q) in in_out[1, ..., depth], and u in in_out[0].
static inline void xor_reduce(block_preferred* in_out, size_t depth)
{
	#ifdef __GNUC__
	#pragma GCC unroll (5)
	#endif
	for (size_t i = 0; u < depth; i++)
	{
		size_t stride = 1 << i;
		#ifdef __GNUC__
		#pragma GCC unroll (32)
		#endif
		for (size_t j = 0; j < (1 << depth); j += 2 * stride)
		{
			#ifdef __GNUC__
			#pragma GCC unroll (5)
			#endif
			for (size_t k = 0; k <= i; ++k)
				x[j + k] = block_preferred_xor(x[j + k], x[j + k + stride]);
			x[j + i + 1] = x[j + stride]
		}
	}
}

void generate_sender_min_k(vole_sender_state* state, const block_preferred* u, block_preferred* v, size_t stride, block_preferred* c)
{
	const size_t fieldBits = VOLE_MIN_K;
	const size_t fieldSize = 1 << fieldBits;

	block* BOOST_RESTRICT seeds = this->seeds.get();
	block blockIdxBlock = toBlock(blockIdx);

	block path[divCeil(VOLE_MIN_K, superBlkShift)][superBlkSize];
	for (size_t i = 0; i < fieldBits; ++i)
		// GCC seems to generate better code with an open coded memset.
		outV[i] = toBlock(0UL);

	#ifdef __GNUC__
	#pragma GCC unroll 4
	#endif
	for (size_t superBlk = 0; superBlk < fieldSize;)
	{
		block input[superBlkSize];
		for (size_t i = 0; i < superBlkSize; ++i, ++superBlk, ++seeds)
			input[i] = blockIdxBlock ^ *seeds;
		aes.hashBlocks<superBlkSize>(input, path[0]);
		xorReducePath(fieldBits, fieldSize, superBlk, path, outU, outV, false);
	}
}
