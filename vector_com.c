#include "vector_com.h"
#include <assert.h>
#include <stdbool.h>

#include "util.h"
#include "small_vole.h"

// TODO: probably can ditch most of the "restrict"s in inlined functions.

#define TREE_CHUNK_SIZE (PRG_TREE_PREFERRED_WIDTH / 2)
#define TREE_CHUNK_SIZE_SHIFT (PRG_TREE_PREFERRED_WIDTH_SHIFT - 1)
#define LEAF_CHUNK_SIZE (PRG_LEAF_PREFERRED_WIDTH / 2)
#define LEAF_CHUNK_SIZE_SHIFT (PRG_LEAF_PREFERRED_WIDTH_SHIFT - 1)

#define TREE_BLOCKS_PER_KEY \
	((2 * sizeof(block_secpar) + sizeof(prg_tree_block) - 1) / sizeof(prg_tree_block))
#define LEAF_BLOCKS_PER_KEY \
	((3 * sizeof(block_secpar) + sizeof(prg_leaf_block) - 1) / sizeof(prg_leaf_block))
#define TREE_BYTES_PER_KEY_REMAINDER \
	((2 * sizeof(block_secpar)) % sizeof(prg_tree_block))
#define LEAF_BYTES_PER_KEY_REMAINDER \
	((3 * sizeof(block_secpar)) % sizeof(prg_leaf_block))

#define MAX_CHUNK_SIZE (LEAF_CHUNK_SIZE > TREE_CHUNK_SIZE ? LEAF_CHUNK_SIZE : TREE_CHUNK_SIZE)

static ALWAYS_INLINE void copy_prg_output(
	bool leaf, size_t n, uint32_t j, uint32_t num_blocks, size_t num_bytes,
	const prg_tree_block* prg_output_tree, const prg_leaf_block* prg_output_leaf,
	block_secpar* output)
{
	size_t outputs_per_key = !leaf ? 2 : 3;
	size_t prg_block_size = !leaf ? sizeof(prg_tree_block) : sizeof(prg_leaf_block);
	for (size_t k = 0; k < n; ++k)
		memcpy(((unsigned char*) &output[outputs_per_key * k]) + j * prg_block_size,
		       !leaf ? (void*) &prg_output_tree[num_blocks * k]
		             : (void*) &prg_output_leaf[num_blocks * k], num_bytes);
}

// Take each of n block_secpars from input and expand it into 2 adjacent blocks in output. If leaf,
// this becomes 3 adjacent blocks. fixed_key_tree, fixed_key_leaf is only used for PRGs based on
// fixed-key Rijndael. Works for n <= TREE_CHUNK_SIZE (or LEAF_CHUNK_SIZE if leaf).
static ALWAYS_INLINE void expand_chunk(
	bool leaf, size_t n,
	const prg_tree_fixed_key* restrict fixed_key_tree,
	const prg_leaf_fixed_key* restrict fixed_key_leaf,
	const block_secpar* restrict input, block_secpar* restrict output)
{
	assert(n <= !leaf ? TREE_CHUNK_SIZE : LEAF_CHUNK_SIZE);

	block_secpar keys[MAX_CHUNK_SIZE];
	prg_tree_iv ivs_tree[TREE_CHUNK_SIZE];
	prg_leaf_iv ivs_leaf[LEAF_CHUNK_SIZE];
	prg_tree_key prgs_tree[TREE_CHUNK_SIZE];
	prg_leaf_key prgs_leaf[LEAF_CHUNK_SIZE];
	prg_tree_block prg_output_tree[TREE_CHUNK_SIZE * TREE_BLOCKS_PER_KEY];
	prg_leaf_block prg_output_leaf[LEAF_CHUNK_SIZE * LEAF_BLOCKS_PER_KEY];

	memcpy(&keys[0], input, n * sizeof(block_secpar));

	// TODO
	memset(&ivs_tree, 0, sizeof(ivs_tree));
	memset(&ivs_leaf, 0, sizeof(ivs_leaf));

	size_t prg_block_size = !leaf ? sizeof(prg_tree_block) : sizeof(prg_leaf_block);
	uint32_t blocks_per_key = !leaf ? TREE_BLOCKS_PER_KEY : LEAF_BLOCKS_PER_KEY;
	size_t bytes_per_key_remainder = !leaf ? TREE_BYTES_PER_KEY_REMAINDER : LEAF_BYTES_PER_KEY_REMAINDER;
	static_assert(TREE_BLOCKS_PER_KEY >= 2);
	static_assert(LEAF_BLOCKS_PER_KEY >= 2);

	uint32_t num_blocks = blocks_per_key % 1 ? 3 : 2;
	if (!leaf)
		prg_tree_init(&prgs_tree[0], fixed_key_tree, &keys[0], &ivs_tree[0],
		              n, num_blocks, 0, &prg_output_tree[0]);
	else
		prg_leaf_init(&prgs_leaf[0], fixed_key_leaf, &keys[0], &ivs_leaf[0],
		              n, num_blocks, 0, &prg_output_leaf[0]);

	assert(blocks_per_key > num_blocks || bytes_per_key_remainder == 0);
	copy_prg_output(leaf, n, 0, num_blocks, num_blocks * prg_block_size,
	                prg_output_tree, prg_output_leaf, output);

	for (uint32_t j = num_blocks; j < blocks_per_key; j += num_blocks)
	{
		// TODO: Make sure this doesn't pull in the whole switch statement (with optimizations).
		num_blocks = 2;
		if (j + num_blocks > blocks_per_key)
			num_blocks = blocks_per_key - j;

		if (!leaf)
			prg_tree_gen(&prgs_tree[0], fixed_key_tree, n, num_blocks, j, &prg_output_tree[0]);
		else
			prg_leaf_gen(&prgs_leaf[0], fixed_key_leaf, n, num_blocks, j, &prg_output_leaf[0]);

		if (j + num_blocks < blocks_per_key || bytes_per_key_remainder == 0)
			copy_prg_output(leaf, n, j, num_blocks, num_blocks * prg_block_size,
			                prg_output_tree, prg_output_leaf, output);
		else
			copy_prg_output(leaf, n, j, num_blocks, bytes_per_key_remainder,
			                prg_output_tree, prg_output_leaf, output);

	}
}

// Allow n to be hardcoded by the compiler into expand_chunk:
#define DEF_EXPAND_CHUNK_N(n) \
	static void expand_chunk_n_##n( \
		const prg_tree_fixed_key* restrict fixed_key_tree, \
		const prg_leaf_fixed_key* restrict fixed_key_leaf, \
		const block_secpar* restrict input, block_secpar* restrict output) \
	{ \
		if (n <= TREE_CHUNK_SIZE) \
			expand_chunk(false, n, fixed_key_tree, fixed_key_leaf, input, output); \
	}

// Most of these will be unused, and so removed by the compiler.
static_assert(TREE_CHUNK_SIZE <= 32);
DEF_EXPAND_CHUNK_N(1)
DEF_EXPAND_CHUNK_N(2)
DEF_EXPAND_CHUNK_N(3)
DEF_EXPAND_CHUNK_N(4)
DEF_EXPAND_CHUNK_N(5)
DEF_EXPAND_CHUNK_N(6)
DEF_EXPAND_CHUNK_N(7)
DEF_EXPAND_CHUNK_N(8)
DEF_EXPAND_CHUNK_N(9)
DEF_EXPAND_CHUNK_N(10)
DEF_EXPAND_CHUNK_N(11)
DEF_EXPAND_CHUNK_N(12)
DEF_EXPAND_CHUNK_N(13)
DEF_EXPAND_CHUNK_N(14)
DEF_EXPAND_CHUNK_N(15)
DEF_EXPAND_CHUNK_N(16)
DEF_EXPAND_CHUNK_N(17)
DEF_EXPAND_CHUNK_N(18)
DEF_EXPAND_CHUNK_N(19)
DEF_EXPAND_CHUNK_N(20)
DEF_EXPAND_CHUNK_N(21)
DEF_EXPAND_CHUNK_N(22)
DEF_EXPAND_CHUNK_N(23)
DEF_EXPAND_CHUNK_N(24)
DEF_EXPAND_CHUNK_N(25)
DEF_EXPAND_CHUNK_N(26)
DEF_EXPAND_CHUNK_N(27)
DEF_EXPAND_CHUNK_N(28)
DEF_EXPAND_CHUNK_N(29)
DEF_EXPAND_CHUNK_N(30)
DEF_EXPAND_CHUNK_N(31)
DEF_EXPAND_CHUNK_N(32)

// Use a switch to select which size. The case should always be resolved at compile time. This is
// just a way to get the compiler to select the right function to call.
static ALWAYS_INLINE void expand_chunk_switch( \
	size_t n, const prg_tree_fixed_key* restrict fixed_key_tree,
	const prg_leaf_fixed_key* restrict fixed_key_leaf, \
	const block_secpar* restrict input, block_secpar* restrict output) \
{ \
	switch (n)
	{
#define EXPAND_CHUNK_SWITCH_CASE(n) \
	case n: \
		expand_chunk_n_##n(fixed_key_tree, fixed_key_leaf, input, output); \
		break;
		EXPAND_CHUNK_SWITCH_CASE(1)
		EXPAND_CHUNK_SWITCH_CASE(2)
		EXPAND_CHUNK_SWITCH_CASE(3)
		EXPAND_CHUNK_SWITCH_CASE(4)
		EXPAND_CHUNK_SWITCH_CASE(5)
		EXPAND_CHUNK_SWITCH_CASE(6)
		EXPAND_CHUNK_SWITCH_CASE(7)
		EXPAND_CHUNK_SWITCH_CASE(8)
		EXPAND_CHUNK_SWITCH_CASE(9)
		EXPAND_CHUNK_SWITCH_CASE(10)
		EXPAND_CHUNK_SWITCH_CASE(11)
		EXPAND_CHUNK_SWITCH_CASE(12)
		EXPAND_CHUNK_SWITCH_CASE(13)
		EXPAND_CHUNK_SWITCH_CASE(14)
		EXPAND_CHUNK_SWITCH_CASE(15)
		EXPAND_CHUNK_SWITCH_CASE(16)
		EXPAND_CHUNK_SWITCH_CASE(17)
		EXPAND_CHUNK_SWITCH_CASE(18)
		EXPAND_CHUNK_SWITCH_CASE(19)
		EXPAND_CHUNK_SWITCH_CASE(20)
		EXPAND_CHUNK_SWITCH_CASE(21)
		EXPAND_CHUNK_SWITCH_CASE(22)
		EXPAND_CHUNK_SWITCH_CASE(23)
		EXPAND_CHUNK_SWITCH_CASE(24)
		EXPAND_CHUNK_SWITCH_CASE(25)
		EXPAND_CHUNK_SWITCH_CASE(26)
		EXPAND_CHUNK_SWITCH_CASE(27)
		EXPAND_CHUNK_SWITCH_CASE(28)
		EXPAND_CHUNK_SWITCH_CASE(29)
		EXPAND_CHUNK_SWITCH_CASE(30)
		EXPAND_CHUNK_SWITCH_CASE(31)
		EXPAND_CHUNK_SWITCH_CASE(32)
	}
}

static void expand_chunk_leaf_n_leaf_chunk_size(
	const prg_tree_fixed_key* restrict fixed_key_tree,
	const prg_leaf_fixed_key* restrict fixed_key_leaf,
	const block_secpar* restrict input, block_secpar* restrict output)
{
	expand_chunk(true, LEAF_CHUNK_SIZE, fixed_key_tree, fixed_key_leaf, input, output);
}

#define PARENT(x) (((x) - 2 * BITS_PER_WITNESS) / 2)
#define FIRST_CHILD(x) (2 * (x) + 2 * BITS_PER_WITNESS)

// Duplicate the same function many times for recursion, so that it will all get inlined.
#define EXPAND_ROOTS_RECURSION(n, next) \
	static ALWAYS_INLINE void expand_roots_##n( \
		bool partial, const prg_tree_fixed_key* restrict fixed_key_tree, \
		const prg_leaf_fixed_key* restrict fixed_key_leaf, \
		block_secpar* restrict forest, size_t i) \
	{ \
		if (n >= TREE_CHUNK_SIZE_SHIFT) \
			return; \
		size_t this_chunk_size = partial ? (2 * BITS_PER_WITNESS) % TREE_CHUNK_SIZE : TREE_CHUNK_SIZE; \
		expand_chunk_switch(this_chunk_size, fixed_key_tree, fixed_key_leaf, &forest[i], &forest[FIRST_CHILD(i)]); \
		next(partial, fixed_key_tree, fixed_key_leaf, forest, FIRST_CHILD(i)); \
		next(partial, fixed_key_tree, fixed_key_leaf, forest, FIRST_CHILD(i) + this_chunk_size); \
	}
#define FINISHED_RECURSION(a,b,c,d,e) do {} while (0)

static_assert(TREE_CHUNK_SIZE_SHIFT <= 5);
EXPAND_ROOTS_RECURSION(4, FINISHED_RECURSION)
EXPAND_ROOTS_RECURSION(3, expand_roots_4)
EXPAND_ROOTS_RECURSION(2, expand_roots_3)
EXPAND_ROOTS_RECURSION(1, expand_roots_2)
#undef FINISHED_RECURSION

static ALWAYS_INLINE void expand_tree(
	bool verifier, size_t delta, const prg_tree_fixed_key* restrict fixed_key_tree,
	const prg_leaf_fixed_key* restrict fixed_key_leaf, block_secpar* restrict forest,
	unsigned int levels_to_expand, size_t index,
	block_secpar* restrict leaves, block_2secpar* restrict hashed_leaves)
{
	if (verifier)
	{
		// If the active path fills up at least 1 LEAF_CHUNK_SIZE block, we need to apply the leaf
		// prgs and write out to leaves and hashed_leaves.
		if (LEAF_CHUNK_SIZE <= TREE_CHUNK_SIZE)
		{
			size_t starting_leaf_idx = delta & -TREE_CHUNK_SIZE;
			size_t starting_node =
				BITS_PER_WITNESS * ((1 << (levels_to_expand + TREE_CHUNK_SIZE_SHIFT)) - 2) +
				(index << (levels_to_expand + TREE_CHUNK_SIZE_SHIFT)) + starting_leaf_idx;
			for (size_t j = 0; j < TREE_CHUNK_SIZE; j += LEAF_CHUNK_SIZE)
			{
				block_secpar prg_output[3 * LEAF_CHUNK_SIZE];
				expand_chunk_leaf_n_leaf_chunk_size(
					fixed_key_tree, fixed_key_leaf, &forest[starting_node + j], prg_output);

				for (size_t k = 0; k < LEAF_CHUNK_SIZE; k += VOLE_WIDTH)
				{
					// Simplest to compute permuted_leaf_idx in each iteration, but
					// vole_permute_key_index leaves the last VOLE_WIDTH_SHIFT bits unchanged, so it
					// only needs to be called once every VOLE_WIDTH blocks.
					size_t leaf_idx = starting_leaf_idx + j + k;
					size_t permuted_leaf_idx = vole_permute_key_index(leaf_idx ^ delta);
					for (size_t l = 0; l < VOLE_WIDTH && l < LEAF_CHUNK_SIZE; l++)
					{
						leaves[permuted_leaf_idx] = prg_output[3 * (k + l)];
						memcpy(&hashed_leaves[leaf_idx], &prg_output[3 * (k + l) + 1], sizeof(block_2secpar));
						leaf_idx++;
						permuted_leaf_idx = (permuted_leaf_idx & -VOLE_WIDTH) |
							((leaf_idx ^ delta) & (VOLE_WIDTH - 1));
					}
				}
			}
		}
	}

	// The verifier has already completed the active path by here, so put the
	// leaf == delta / TREE_CHUNK_SIZE iteration first, and skip it.
	for (size_t i = verifier ? 1 : 0; i < (1 << levels_to_expand); ++i)
	{
		size_t leaf = i ^ (delta / TREE_CHUNK_SIZE);

		unsigned int generations_from_ancestor = count_trailing_zeros(i | (1 << levels_to_expand));
		unsigned int ancestor_level = levels_to_expand - generations_from_ancestor;

		size_t ancestor =
			BITS_PER_WITNESS * ((TREE_CHUNK_SIZE << ancestor_level) - 2) +
			TREE_CHUNK_SIZE * ((index << ancestor_level) + (leaf >> generations_from_ancestor));

		for (int d = generations_from_ancestor - 1; d >= 0; --d)
		{
			size_t first_child = FIRST_CHILD(ancestor);
			expand_chunk_switch(TREE_CHUNK_SIZE, fixed_key_tree, fixed_key_leaf,
			                    &forest[ancestor], &forest[first_child]);
			// More straightforward to add TREE_CHUNK_SIZE times the dth bit of leaf, but we have leaf ==
			// i ^ (delta / TREE_CHUNK_SIZE), and i has generations_from_ancestor trailing zeros, so this
			// is equivalent:
			ancestor = first_child + ((delta >> d) & TREE_CHUNK_SIZE);
		}

		// If this ends a block of size at least LEAF_CHUNK_SIZE, then apply the leaf prgs and write
		// to leaves and hashed_leaves.
		size_t leaf_node = ancestor;
		if (LEAF_CHUNK_SIZE <= TREE_CHUNK_SIZE || (i + 1) % (LEAF_CHUNK_SIZE / TREE_CHUNK_SIZE) == 0)
		{
			size_t starting_node = leaf_node - (TREE_CHUNK_SIZE * leaf) % MAX_CHUNK_SIZE;
			size_t starting_leaf_idx = TREE_CHUNK_SIZE * leaf - (TREE_CHUNK_SIZE * leaf) % MAX_CHUNK_SIZE;
			for (size_t j = 0; j < MAX_CHUNK_SIZE; j += LEAF_CHUNK_SIZE)
			{
				block_secpar prg_output[3 * LEAF_CHUNK_SIZE];
				expand_chunk_leaf_n_leaf_chunk_size(
					fixed_key_tree, fixed_key_leaf, &forest[starting_node + j], prg_output);

				for (size_t k = 0; k < LEAF_CHUNK_SIZE; k += VOLE_WIDTH)
				{
					// Simplest to compute permuted_leaf_idx in each iteration, but
					// vole_permute_key_index leaves the last VOLE_WIDTH_SHIFT bits unchanged, so it
					// only needs to be called once every VOLE_WIDTH blocks.
					size_t leaf_idx = starting_leaf_idx + j + k;
					size_t permuted_leaf_idx = vole_permute_key_index(leaf_idx ^ delta);
					for (size_t l = 0; l < VOLE_WIDTH && l < LEAF_CHUNK_SIZE; l++)
					{
						leaves[permuted_leaf_idx] = prg_output[3 * (k + l)];
						memcpy(&hashed_leaves[leaf_idx], &prg_output[3 * (k + l) + 1], sizeof(block_2secpar));
						leaf_idx++;
						if (verifier)
							permuted_leaf_idx = (permuted_leaf_idx & -VOLE_WIDTH) |
								((leaf_idx ^ delta) & (VOLE_WIDTH - 1));
						else
							// Equivalent because delta == 0, but the compiler can't figure this out.
							permuted_leaf_idx++;
					}
				}
			}
		}
	}
}

void vector_commit(
	const block_secpar* restrict roots,
	const prg_tree_fixed_key* restrict fixed_key_tree, const prg_leaf_fixed_key* restrict fixed_key_leaf,
	block_secpar* restrict forest, block_secpar* restrict leaves,
	block_2secpar* restrict hashed_leaves)
{
	memcpy(forest, roots, 2 * BITS_PER_WITNESS * sizeof(block_secpar));

	// First expand each tree far enough to have TREE_CHUNK_SIZE nodes.
	static_assert(VOLE_MIN_K >= TREE_CHUNK_SIZE_SHIFT);
	for (size_t i = 0; i + TREE_CHUNK_SIZE <= 2 * BITS_PER_WITNESS; i += TREE_CHUNK_SIZE)
		expand_roots_1(false, fixed_key_tree, fixed_key_leaf, forest, i);
	size_t remaining = (2 * BITS_PER_WITNESS) % TREE_CHUNK_SIZE;
	if (remaining)
		expand_roots_1(true, fixed_key_tree, fixed_key_leaf, forest, 2 * BITS_PER_WITNESS - remaining);

	// Expand each tree, now that they are each 1 chunk in size.
	for (size_t i = 0; i < BITS_PER_WITNESS; ++i)
	{
		// First VOLES_MAX_K trees are 1 depth bigger.
		unsigned int depth = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
		expand_tree(false, 0, fixed_key_tree, fixed_key_leaf, forest,
		            depth - TREE_CHUNK_SIZE_SHIFT, i, leaves, hashed_leaves);
		leaves += (1 << depth);
		hashed_leaves += (1 << depth);
	}
}

void vector_open(
	const block_secpar* restrict forest, const block_2secpar* restrict hashed_leaves,
	const unsigned char* restrict delta, unsigned char* restrict opening)
{
	for (size_t i = 0; i < BITS_PER_WITNESS; ++i)
	{
		unsigned int depth = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
		size_t node = 2 * i;
		size_t leaf_idx = 0;
		for (unsigned int d = 1; d <= depth; ++d)
		{
			unsigned int hole = delta[depth - d] & 1;
			leaf_idx = 2*leaf_idx + hole;

			node = node + hole;
			memcpy(opening, &forest[node ^ 1], sizeof(block_secpar));
			opening += sizeof(block_secpar);
			node = FIRST_CHILD(node);
		}

		memcpy(opening, &hashed_leaves[leaf_idx], sizeof(block_2secpar));
		opening += sizeof(block_2secpar);

		delta += depth;
		hashed_leaves += (1 << depth);
	}
}

#define VERIFIER_SUBTREES_PARENT(x) (((x) - SECURITY_PARAM) / 2)
#define VERIFIER_SUBTREES_FIRST_CHILD(x) (2 * (x) + SECURITY_PARAM)

#define EXPAND_VERIFIER_SUBTREES_RECURSION(n, next) \
	static ALWAYS_INLINE void expand_verifier_subtrees_##n( \
		size_t this_chunk_size, const prg_tree_fixed_key* restrict fixed_key_tree, \
		const prg_leaf_fixed_key* restrict fixed_key_leaf, \
		block_secpar* restrict forest, size_t i, size_t node) \
	{ \
		if (n >= TREE_CHUNK_SIZE_SHIFT) \
			return; \
		size_t level_lim = (SECURITY_PARAM - (n + 1) * BITS_PER_WITNESS) << n; \
		if (i >= level_lim) \
			return; \
		if (i + this_chunk_size > level_lim) \
		{ \
			/* Should always equal level_lim - i, because all preceding calls were on whole chunks. */ \
			this_chunk_size = level_lim % TREE_CHUNK_SIZE; \
			size_t child = VERIFIER_SUBTREES_FIRST_CHILD(node); \
			expand_chunk_switch(this_chunk_size, fixed_key_tree, fixed_key_leaf, &forest[node], &forest[child]); \
			size_t output_size = 2 * this_chunk_size; \
			i *= 2; \
			if (output_size >= TREE_CHUNK_SIZE) \
			{ \
				next(TREE_CHUNK_SIZE, fixed_key_tree, fixed_key_leaf, forest, i, child); \
				i += TREE_CHUNK_SIZE; \
				child += TREE_CHUNK_SIZE; \
				output_size -= TREE_CHUNK_SIZE; \
			} \
			next(output_size, fixed_key_tree, fixed_key_leaf, forest, i, child); \
		} \
		else \
		{ \
			/* this_chunk_size must be TREE_CHUNK_SIZE here, because at most the last call is not on a */ \
			/* whole chunk, and that call will be the one that hits the level_lim limit above. */ \
			size_t child = VERIFIER_SUBTREES_FIRST_CHILD(node); \
			expand_chunk_switch(TREE_CHUNK_SIZE, fixed_key_tree, fixed_key_leaf, &forest[node], &forest[child]); \
			next(TREE_CHUNK_SIZE, fixed_key_tree, fixed_key_leaf, forest, 2*i, child); \
			next(TREE_CHUNK_SIZE, fixed_key_tree, fixed_key_leaf, forest, 2*i + TREE_CHUNK_SIZE, child + TREE_CHUNK_SIZE); \
		} \
	}
#define FINISHED_RECURSION(a,b,c,d,e,f) do {} while (0)

static_assert(TREE_CHUNK_SIZE_SHIFT <= 5);
EXPAND_VERIFIER_SUBTREES_RECURSION(4, FINISHED_RECURSION)
EXPAND_VERIFIER_SUBTREES_RECURSION(3, expand_verifier_subtrees_4)
EXPAND_VERIFIER_SUBTREES_RECURSION(2, expand_verifier_subtrees_3)
EXPAND_VERIFIER_SUBTREES_RECURSION(1, expand_verifier_subtrees_2)
EXPAND_VERIFIER_SUBTREES_RECURSION(0, expand_verifier_subtrees_1)
#undef FINISHED_RECURSION

static ALWAYS_INLINE void reorder_verifier_keys(
	const unsigned char* opening, block_secpar* reordered_keys)
{
	block_secpar* dst = reordered_keys;
	for (size_t i = 0; i < VOLE_MAX_K; ++i)
	{
		size_t src_idx = i;
		for (size_t j = 0; j < VOLES_MAX_K; ++j, ++dst, src_idx += VOLE_MAX_K + 2)
			memcpy(dst, &opening[src_idx * sizeof(block_secpar)], sizeof(block_secpar));
		if (i < VOLE_MIN_K)
			for (size_t j = 0; j < VOLES_MIN_K; ++j, ++dst, src_idx += VOLE_MIN_K + 2)
				memcpy(dst, &opening[src_idx * sizeof(block_secpar)], sizeof(block_secpar));
	}
}

void vector_verify(
	const unsigned char* restrict opening, const prg_tree_fixed_key* restrict fixed_key_tree,
	const prg_leaf_fixed_key* restrict fixed_key_leaf, const unsigned char* restrict delta,
	block_secpar* restrict leaves, block_2secpar* restrict hashed_leaves)
{
	block_secpar verifier_subtrees[SECURITY_PARAM * (2 * TREE_CHUNK_SIZE - 1)];

	// Need the keys in transposed order.
	reorder_verifier_keys(opening, verifier_subtrees);

	// Expand all subtrees from opening to depth TREE_CHUNK_SIZE_SHIFT, except for the ones too close to
	// the leaves, which get expanded fewer times. Splitting it up by d like this isn't necessary,
	// as the expand_verifier_subtrees_* functions already take case of splitting it up. It just
	// helps the compiler to see what things are constant.
	size_t i = 0;
	#ifdef __GNUC__
	#pragma GCC unroll (5)
	#endif
	for (unsigned int d = TREE_CHUNK_SIZE_SHIFT; d > 0; --d)
	{
		// Expand subtrees that fully use depth d.
		size_t end = SECURITY_PARAM - d * BITS_PER_WITNESS;
		for (; (i + TREE_CHUNK_SIZE) <= end; i += TREE_CHUNK_SIZE)
			expand_verifier_subtrees_0(TREE_CHUNK_SIZE, fixed_key_tree, fixed_key_leaf, verifier_subtrees, i, i);

		// Expand the subtree that partially reaches depth d, but also has parts that only reach d-1
		// or less. But only if this subtree exists.
		if (end % TREE_CHUNK_SIZE != 0)
		{
			// i == end - end % TREE_CHUNK_SIZE should hold here.
			expand_verifier_subtrees_0(TREE_CHUNK_SIZE, fixed_key_tree, fixed_key_leaf, verifier_subtrees, i, i);
			i += TREE_CHUNK_SIZE;
		}
	}

	block_secpar forest[VECTOR_COMMIT_NODES];

	for (i = 0; i < BITS_PER_WITNESS; ++i)
	{
		// Copy the subtrees into the forest. We only need to copy the leaves of the subtrees, as
		// the interior nodes are unused.
		unsigned int depth = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
		size_t verifier_subtrees_node = VERIFIER_SUBTREES_FIRST_CHILD(i);
		size_t forest_node = 2 * i;
		size_t this_delta = 0;
		unsigned int d = 1;
		while (true)
		{
			unsigned int hole = delta[depth - d] & 1;
			this_delta = 2*this_delta + hole;

			size_t copy_input_node = verifier_subtrees_node + (1 - hole);
			size_t copy_output_node = forest_node + (1 - hole);
			size_t copy_depth = depth - d > TREE_CHUNK_SIZE_SHIFT ? TREE_CHUNK_SIZE_SHIFT : depth - d;

			// Same as iterating VERIFIER_SUBTREES_FIRST_CHILD (resp. FIRST_CHILD) copy_depth times.
			copy_input_node = (copy_input_node << copy_depth) + ((1 << copy_depth) - 1) * VERIFIER_SUBTREES_FIRST_CHILD(0);
			copy_output_node = (copy_output_node << copy_depth) + ((1 << copy_depth) - 1) * FIRST_CHILD(0);

			memcpy(&forest[copy_output_node], &verifier_subtrees[copy_input_node], sizeof(block_secpar) << copy_depth);

			if (d < depth)
			{
				verifier_subtrees_node = VERIFIER_SUBTREES_FIRST_CHILD(verifier_subtrees_node + hole);
				forest_node = FIRST_CHILD(forest_node + hole);
				++d;
			}
			else
				break;
		}

		// forest_node currently contains the 1 leaf node we cannot compute. At least stop it from
		// being uninitialized memory.
		memset(&forest[forest_node], 0, sizeof(block_secpar));

		// Expand the rest of this tree.
		expand_tree(true, this_delta, fixed_key_tree, fixed_key_leaf, forest,
		            depth - TREE_CHUNK_SIZE_SHIFT, i, leaves, hashed_leaves);

		// Currently leaves[0] and hashed_leaves[this_delta] contain garbage (specifically, PRG(0)),
		// because we don't know the keys on the active path. Fix them up.
		memset(&leaves[0], 0, sizeof(block_secpar));
		memcpy(&hashed_leaves[this_delta], opening + depth * sizeof(block_secpar), sizeof(block_2secpar));

		leaves += (1 << depth);
		hashed_leaves += (1 << depth);
		opening += (depth + 2) * sizeof(block_secpar);
		delta += depth;
	}
}
