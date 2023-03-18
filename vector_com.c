#include "vector_com.h"
#include <assert.h>
#include <stdbool.h>

#include "util.h"
#include "small_vole.h"

// TODO: probably can ditch most of the "restrict"s in inlined functions.

#if defined(TREE_PRG_AES_CTR)
typedef aes_round_keys tree_cipher_round_keys;
typedef block128 tree_cipher_block;
#define CHUNK_SIZE AES_PREFERRED_WIDTH
#elif defined(TREE_PRG_RIJNDAEL_EVEN_MANSOUR)
typedef rijndael_round_keys tree_cipher_round_keys;
typedef block_secpar tree_cipher_block;
#define CHUNK_SIZE FIXED_KEY_PREFERRED_WIDTH
#endif

#if defined(LEAF_PRG_AES_CTR)
typedef aes_round_keys leaf_cipher_round_keys;
typedef block128 leaf_cipher_block;
#define LEAF_CHUNK_SIZE AES_PREFERRED_WIDTH
#elif defined(LEAF_PRG_RIJNDAEL_EVEN_MANSOUR)
typedef rijndael_round_keys leaf_cipher_round_keys;
typedef block_secpar leaf_cipher_block;
#define LEAF_CHUNK_SIZE FIXED_KEY_PREFERRED_WIDTH
#endif

#define MAX_CHUNK_SIZE (LEAF_CHUNK_SIZE > CHUNK_SIZE ? LEAF_CHUNK_SIZE : CHUNK_SIZE)

#define PARENT(x) (((x) - 2 * BITS_PER_WITNESS) / 2)
#define FIRST_CHILD(x) (2 * (x) + 2 * BITS_PER_WITNESS)

// Returns true if output was generated along with the key.
static ALWAYS_INLINE bool tree_prg_keygen(
	tree_cipher_round_keys* restrict round_keys, const block_secpar* restrict keys,
	tree_cipher_block* restrict output)
{
#if defined(TREE_PRG_AES_CTR)
	aes_keygen_ctr_x2(round_keys, keys, 0, output);
	return true;
#else
	return false;
#endif
}

static ALWAYS_INLINE void tree_prg_eval(
	size_t counter, const tree_cipher_round_keys* restrict round_keys,
	const rijndael_round_keys* restrict fixed_key, const block_secpar* restrict keys,
	tree_cipher_block* restrict output)
{
#if defined(TREE_PRG_AES_CTR)
	aes_ctr_x1(round_keys, counter, output);
#elif defined(TREE_PRG_RIJNDAEL_EVEN_MANSOUR)
	rijndael_ctr_fixed_key_x2(fixed_key, keys, counter, output);
#endif
}

static ALWAYS_INLINE void tree_prg_eval_x2(
	size_t counter, const tree_cipher_round_keys* restrict round_keys,
	const rijndael_round_keys* restrict fixed_key, const block_secpar* restrict keys,
	tree_cipher_block* restrict output)
{
#if defined(TREE_PRG_AES_CTR)
	aes_ctr_x2(round_keys, counter, output);
#elif defined(TREE_PRG_RIJNDAEL_EVEN_MANSOUR)
	rijndael_ctr_fixed_key_x2(fixed_key, keys, counter, output);
#endif
}

static ALWAYS_INLINE bool leaf_prg_keygen(
	leaf_cipher_round_keys* restrict round_keys, const block_secpar* restrict keys,
	leaf_cipher_block* restrict output)
{
#if defined(LEAF_PRG_AES_CTR)
	aes_keygen_ctr_x2(round_keys, keys, 0, output);
	return true;
#else
	return false;
#endif
}

static ALWAYS_INLINE void leaf_prg_eval(
	size_t counter, const leaf_cipher_round_keys* restrict round_keys,
	const rijndael_round_keys* restrict fixed_key, const block_secpar* restrict keys,
	leaf_cipher_block* restrict output)
{
#if defined(LEAF_PRG_AES_CTR)
	aes_ctr_x1(round_keys, counter, output);
#elif defined(LEAF_PRG_RIJNDAEL_EVEN_MANSOUR)
	rijndael_ctr_fixed_key_x2(fixed_key, keys, counter, output);
#endif
}

static ALWAYS_INLINE void leaf_prg_eval_x2(
	size_t counter, const leaf_cipher_round_keys* restrict round_keys,
	const rijndael_round_keys* restrict fixed_key, const block_secpar* restrict keys,
	leaf_cipher_block* restrict output)
{
#if defined(LEAF_PRG_AES_CTR)
	aes_ctr_x2(round_keys, counter, output);
#elif defined(LEAF_PRG_RIJNDAEL_EVEN_MANSOUR)
	rijndael_ctr_fixed_key_x2(fixed_key, keys, counter, output);
#endif
}

static ALWAYS_INLINE void expand_partial_chunk(
	bool leaf, size_t n,
	const rijndael_round_keys* restrict fixed_key,
	tree_cipher_round_keys* restrict round_keys_tree,
	leaf_cipher_round_keys* restrict round_keys_leaf,
	const block_secpar* restrict input, block_secpar* restrict output)
{
	block_secpar keys[MAX_CHUNK_SIZE / 2];
	tree_cipher_block cipher_output_tree[CHUNK_SIZE];
	leaf_cipher_block cipher_output_leaf[LEAF_CHUNK_SIZE];

	// Pad input to avoid using uninitialized memory.
	memcpy(keys, input, n * sizeof(block_secpar));
	memset(keys + n, 0, (MAX_CHUNK_SIZE / 2 - n) * sizeof(block_secpar));

	size_t j = 0;
	size_t outputs_per_key = !leaf ? 2 : 3;
	size_t j_inc = !leaf ? 2 * sizeof(tree_cipher_block) : 2 * sizeof(leaf_cipher_block);

	if (!leaf)
	{
		if (tree_prg_keygen(round_keys_tree, keys, cipher_output_tree))
			goto have_cipher_output;
	}
	else
	{
		if (leaf_prg_keygen(round_keys_leaf, keys, cipher_output_leaf))
			goto have_cipher_output;
	}

	for (; (j + j_inc) <= outputs_per_key * sizeof(block_secpar); j += j_inc)
	{
		if (!leaf)
			tree_prg_eval_x2(2 * j / j_inc, round_keys_tree, fixed_key, keys, cipher_output_tree);
		else
			leaf_prg_eval_x2(2 * j / j_inc, round_keys_leaf, fixed_key, keys, cipher_output_leaf);

have_cipher_output:
		for (size_t k = 0; k < n; ++k)
			memcpy(((unsigned char*) &output[outputs_per_key * k]) + j,
			       !leaf ? &cipher_output_tree[2 * k] : &cipher_output_leaf[2 * k], j_inc);
	}
}

// Takes each block from input and expands it into 2 adjacent blocks in output. If leaf, this
// becomes 3 adjacent blocks. fixed_key is only used for PRGs based on fixed-key Rijndael. Works
// for n <= CHUNK_SIZE (or LEAF_CHUNK_SIZE if leaf).
static ALWAYS_INLINE void expand_chunk(
	bool leaf, size_t n, const rijndael_round_keys* restrict fixed_key,
	const block_secpar* restrict input, block_secpar* restrict output)
{
	tree_cipher_round_keys round_keys_tree[CHUNK_SIZE];
	leaf_cipher_round_keys round_keys_leaf[LEAF_CHUNK_SIZE];

	size_t chunk_size = leaf ? CHUNK_SIZE : LEAF_CHUNK_SIZE;

	size_t first_part = (n < chunk_size / 2) ? n : chunk_size / 2;
	expand_partial_chunk(
		leaf, first_part, fixed_key, &round_keys_tree[0], &round_keys_leaf[0], &input[0], &output[0]);
	size_t second_part = n - first_part;

	if (second_part > 0)
		expand_partial_chunk(
			leaf, second_part, fixed_key, &round_keys_tree[first_part], &round_keys_leaf[first_part],
			&input[first_part], &output[2 * first_part]);

	static_assert((2 * sizeof(block_secpar)) % (2 * sizeof(tree_cipher_block)) <= sizeof(tree_cipher_block));
	static_assert((3 * sizeof(block_secpar)) % (2 * sizeof(leaf_cipher_block)) <= sizeof(leaf_cipher_block));

	size_t outputs_per_key = !leaf ? 2 : 3;
	size_t j_inc = !leaf ? 2 * sizeof(tree_cipher_block) : 2 * sizeof(leaf_cipher_block);
	size_t j_remaining = (outputs_per_key * sizeof(block_secpar)) % j_inc;
	if (j_remaining != 0)
	{
		// Combine the 2 parts when geting the last block of output for all key.

		tree_cipher_block cipher_output_tree[CHUNK_SIZE];
		leaf_cipher_block cipher_output_leaf[LEAF_CHUNK_SIZE];
		block_secpar keys[MAX_CHUNK_SIZE];
		memcpy(keys, input, n * sizeof(block_secpar));
		memset(keys + n, 0, (MAX_CHUNK_SIZE - n) * sizeof(block_secpar));

		size_t j = (outputs_per_key * sizeof(block_secpar)) - j_remaining;
		if (!leaf)
			tree_prg_eval(2 * j / j_inc, round_keys_tree, fixed_key, keys, cipher_output_tree);
		else
			leaf_prg_eval(2 * j / j_inc, round_keys_leaf, fixed_key, keys, cipher_output_leaf);
		for (size_t k = 0; k < n; ++k)
			memcpy(((unsigned char*) &output[outputs_per_key * k]) + j,
			       !leaf ? &cipher_output_tree[k] : &cipher_output_leaf[k], j_remaining);
	}
}

// Allow n to be hardcoded by the compiler into expand_chunk:
static void expand_chunk_n_chunk_size(
	const rijndael_round_keys* restrict fixed_key,
	const block_secpar* restrict input, block_secpar* restrict output)
{
	expand_chunk(false, CHUNK_SIZE, fixed_key, input, output);
}
static void expand_chunk_n_remainder(
	const rijndael_round_keys* restrict fixed_key,
	const block_secpar* restrict input, block_secpar* restrict output)
{
	expand_chunk(false, (2 * BITS_PER_WITNESS) % CHUNK_SIZE, fixed_key, input, output);
}

static void expand_chunk_leaf_n_leaf_chunk_size(
	const rijndael_round_keys* restrict fixed_key,
	const block_secpar* restrict input, block_secpar* restrict output)
{
	expand_chunk(true, LEAF_CHUNK_SIZE, fixed_key, input, output);
}

// Duplicate the same function many times for recursion, so that it will all get inlined.
#define EXPAND_ROOTS_RECURSION(n, next) \
	static ALWAYS_INLINE void expand_roots_##n( \
		bool partial, const rijndael_round_keys* restrict fixed_key, \
		block_secpar* restrict forest, size_t i) \
	{ \
		if ((1 << n) >= CHUNK_SIZE) \
			return; \
		if (partial) \
			expand_chunk_n_remainder(fixed_key, &forest[i], &forest[FIRST_CHILD(i)]); \
		else \
			expand_chunk_n_chunk_size(fixed_key, &forest[i], &forest[FIRST_CHILD(i)]); \
		size_t this_chunk_size = partial ? (2 * BITS_PER_WITNESS) % CHUNK_SIZE : CHUNK_SIZE; \
		next(partial, fixed_key, forest, FIRST_CHILD(i)); \
		next(partial, fixed_key, forest, FIRST_CHILD(i) + this_chunk_size); \
	}
#define FINISHED_RECURSION(a,b,c,d) do {} while (0)

static_assert(CHUNK_SIZE <= (1 << 5));
EXPAND_ROOTS_RECURSION(5, FINISHED_RECURSION)
EXPAND_ROOTS_RECURSION(4, expand_roots_5)
EXPAND_ROOTS_RECURSION(3, expand_roots_4)
EXPAND_ROOTS_RECURSION(2, expand_roots_3)
EXPAND_ROOTS_RECURSION(1, expand_roots_2)

static ALWAYS_INLINE void expand_tree(
	bool verifier,
	const rijndael_round_keys* restrict fixed_key, block_secpar* restrict forest,
	unsigned int levels_to_expand, size_t index,
	block_secpar* restrict leaves, block_2secpar* restrict hashed_leaves)
{
	for (size_t leaf = 0; leaf < (1 << levels_to_expand); ++leaf)
	{
		unsigned int generations_from_ancestor =
			count_trailing_zeros(leaf | (1 << (levels_to_expand - 1))) + 1;
		unsigned int ancestor_level = levels_to_expand - generations_from_ancestor;

		size_t ancestor =
			BITS_PER_WITNESS * ((CHUNK_SIZE << ancestor_level) - 2) +
			CHUNK_SIZE * ((leaf >> generations_from_ancestor) + (index << ancestor_level));

		for (int i = generations_from_ancestor - 1; i >= 0; --i)
		{
			size_t child = FIRST_CHILD(ancestor) + CHUNK_SIZE * ((leaf >> i) & 1);
			expand_chunk_n_chunk_size(fixed_key, &forest[ancestor], &forest[child]);
			ancestor = child;
		}

		// If this ends a block of size at least LEAF_CHUNK_SIZE, then apply the leaf prgs and write
		// to leaves and hashed_leaves.
		size_t leaf_node = ancestor;
		if (LEAF_CHUNK_SIZE <= CHUNK_SIZE || (leaf + 1) % (LEAF_CHUNK_SIZE / CHUNK_SIZE) == 0)
		{
			size_t starting_node = leaf_node + CHUNK_SIZE - MAX_CHUNK_SIZE;
			size_t starting_leaf_idx = (leaf + 1) * CHUNK_SIZE - MAX_CHUNK_SIZE;
			for (size_t j = 0; j < MAX_CHUNK_SIZE; j += LEAF_CHUNK_SIZE)
			{
				block_secpar prg_output[3 * LEAF_CHUNK_SIZE];
				expand_chunk_leaf_n_leaf_chunk_size(fixed_key, &forest[starting_node + j], prg_output);

				for (size_t k = 0; k < LEAF_CHUNK_SIZE; k += VOLE_WIDTH)
				{
					// Simplest to compute permuted_leaf_idx in each iteration, but it's equivalent
					// to increment it normally, except on VOLE_WIDTH boundaries.
					size_t leaf_idx = starting_leaf_idx + j + k;
					size_t permuted_leaf_idx = vole_permute_key_index(leaf_idx);
					for (size_t l = 0; l < VOLE_WIDTH && l < LEAF_CHUNK_SIZE; l++)
					{
						leaves[permuted_leaf_idx++] = prg_output[3 * (k + l)];
						memcpy(&hashed_leaves[leaf_idx++], &prg_output[3 * (k + l) + 1], sizeof(block_2secpar));
					}
				}
			}
		}
	}
}

void vector_commit(
	const block_secpar* restrict roots, const rijndael_round_keys* restrict fixed_key,
	block_secpar* restrict forest, block_secpar* restrict leaves,
	block_2secpar* restrict hashed_leaves)
{
	memcpy(forest, roots, 2 * BITS_PER_WITNESS * sizeof(block_secpar));

	// First expand each tree far enough to have CHUNK_SIZE nodes.
	static_assert((1 << VOLE_MIN_K) >= CHUNK_SIZE);
	for (size_t i = 0; i + CHUNK_SIZE <= 2 * BITS_PER_WITNESS; i += CHUNK_SIZE)
		expand_roots_1(false, fixed_key, forest, i);
	size_t remaining = (2 * BITS_PER_WITNESS) % CHUNK_SIZE;
	if (remaining)
		expand_roots_1(true, fixed_key, forest, 2 * BITS_PER_WITNESS - remaining);

	// Get the first node at the level where every tree has CHUNK_SIZE nodes.
	size_t first_node = 0;
	unsigned int current_depth = 0;
	for (current_depth = 1; (1 << current_depth) < CHUNK_SIZE; ++current_depth)
		first_node = FIRST_CHILD(first_node);

	// Expand each tree, now that they are each 1 chunk in size.
	for (size_t i = 0; i < BITS_PER_WITNESS; ++i)
	{
		// First VOLES_MAX_K trees are 1 depth bigger.
		unsigned int depth = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
		expand_tree(false, fixed_key, forest, depth - current_depth, i, leaves, hashed_leaves);
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
		for (unsigned int d = 0; d < depth; ++d)
		{
			unsigned int hole = delta[depth - 1 - d] & 1;
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

void vector_verify(
	const unsigned char* restrict opening, const rijndael_round_keys* restrict fixed_key,
	const unsigned char* restrict delta,
	block_secpar* restrict leaves, block_2secpar* restrict hashed_leaves)
{
	block_secpar forest[VECTOR_COMMIT_NODES];
}
