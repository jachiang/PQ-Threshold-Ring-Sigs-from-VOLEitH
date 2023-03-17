#include "vector_com.h"
#include <assert.h>
#include <stdbool.h>

#include "util.h"

#if defined(TREE_PRG_AES_CTR)
typedef aes_round_keys ggm_cipher_round_keys;
typedef block128 ggm_cipher_block;
inline ggm_cipher_block ggm_cipher_block_xor(ggm_cipher_block x, ggm_cipher_block y) { return block128_xor(x, y); }
inline ggm_cipher_block ggm_cipher_block_set_low64(uint64_t x) { return block128_set_low64(x); }
#define CHUNK_SIZE AES_PREFERRED_WIDTH
#elif defined(TREE_PRG_RIJNDAEL_EVEN_MANSOUR)
typedef rijndael_round_keys ggm_cipher_round_keys;
typedef block_secpar ggm_cipher_block;
inline ggm_cipher_block ggm_cipher_block_xor(ggm_cipher_block x, ggm_cipher_block y) { return block_secpar_xor(x, y); }
inline ggm_cipher_block ggm_cipher_block_set_low64(uint64_t x) { return block_secpar_set_low64(x); }
#define CHUNK_SIZE FIXED_KEY_PREFERRED_WIDTH
#endif

#define PARENT(x) (((x) - 2 * BITS_PER_WITNESS) / 2)
#define FIRST_CHILD(x) (2 * (x) + 2 * BITS_PER_WITNESS)

// Returns true if output was generated along with the key.
static ALWAYS_INLINE bool prg_keygen(
	ggm_cipher_round_keys* restrict round_keys, const block_secpar* restrict keys,
	ggm_cipher_block* restrict output)
{
#if defined(TREE_PRG_AES_CTR)
	ggm_cipher_block input[CHUNK_SIZE];
	for (size_t l = 0; l < CHUNK_SIZE/2; ++l)
		// TODO: should it start counting from a random value instead of 0?
		for (size_t m = 0; m < 2; ++m)
			input[l * 2 + m] = ggm_cipher_block_set_low64(m);
	aes_keygen_encrypt_x2(round_keys, keys, input, output);
	return true;
#else
	return false;
#endif
}

static ALWAYS_INLINE void prg_eval_x2(
	size_t counter, const ggm_cipher_round_keys* restrict round_keys,
	const rijndael_round_keys* restrict fixed_key, const block_secpar* restrict keys,
	ggm_cipher_block* restrict output)
{
	ggm_cipher_block input[CHUNK_SIZE];
	for (size_t l = 0; l < CHUNK_SIZE / 2; ++l)
		for (size_t m = 0; m < 2; ++m)
			input[l * 2 + m] = ggm_cipher_block_set_low64(counter + m);

#if defined(TREE_PRG_AES_CTR)
	aes_encrypt_x2(round_keys, input, output);

#elif defined(TREE_PRG_RIJNDAEL_EVEN_MANSOUR)
	for (size_t l = 0; l < CHUNK_SIZE / 2; ++l)
		for (size_t m = 0; m < 2; ++m)
			input[l * 2 + m] = ggm_cipher_block_xor(input[l * 2 + m], keys[l]);
	rijndael_encrypt_fixed_key(fixed_key, input, output);
	for (size_t l = 0; l < CHUNK_SIZE / 2; ++l)
		for (size_t m = 0; m < 2; ++m)
			output[l * 2 + m] = ggm_cipher_block_xor(output[l * 2 + m], keys[l]);
#endif
}

static ALWAYS_INLINE void prg_eval(
	size_t counter, const ggm_cipher_round_keys* restrict round_keys,
	const rijndael_round_keys* restrict fixed_key, const block_secpar* restrict keys,
	ggm_cipher_block* restrict output)
{
	ggm_cipher_block input[CHUNK_SIZE];
	for (size_t l = 0; l < CHUNK_SIZE; ++l)
		input[l] = ggm_cipher_block_set_low64(counter);

#if defined(TREE_PRG_AES_CTR)
	aes_encrypt(round_keys, input, output);

#elif defined(TREE_PRG_RIJNDAEL_EVEN_MANSOUR)
	for (size_t l = 0; l < CHUNK_SIZE / 2; ++l)
		input[l] = ggm_cipher_block_xor(input[l], keys[l]);
	rijndael_encrypt_fixed_key(fixed_key, input, output);
	for (size_t l = 0; l < CHUNK_SIZE / 2; ++l)
		output[l] = ggm_cipher_block_xor(output[l], keys[l]);
#endif
}

static ALWAYS_INLINE void expand_partial_chunk(
	size_t n,
	const rijndael_round_keys* restrict fixed_key, ggm_cipher_round_keys* restrict round_keys,
	const block_secpar* restrict prev_level, block_secpar* restrict next_level)
{
	block_secpar keys[CHUNK_SIZE / 2];
	ggm_cipher_block cipher_output[CHUNK_SIZE];

	// Pad input to avoid using uninitialized memory.
	memcpy(keys, prev_level, n * sizeof(block_secpar));
	memset(keys + n, 0, (CHUNK_SIZE / 2 - n) * sizeof(block_secpar));

	size_t j = 0;
	if (prg_keygen(round_keys, keys, cipher_output))
		goto have_cipher_output;

	for (; (j + 2) <= (2 * sizeof(block_secpar)) / sizeof(ggm_cipher_block); j += 2)
	{
		prg_eval_x2(j, round_keys, fixed_key, keys, cipher_output);

have_cipher_output:
		for (size_t k = 0; k < n; ++k)
			memcpy(((ggm_cipher_block*) &next_level[2 * k]) + j,
			       &cipher_output[2 * k], 2 * sizeof(ggm_cipher_block));
	}
}

// Takes each block from prev_level and expands it into two adjacent blocks in next_level. fixed_key
// is only used for PRGs based on fixed-key Rijndael. Works for n <= CHUNK_SIZE.
// TODO: Parameterize based on expansion factor.
static ALWAYS_INLINE void expand_level(
	size_t n, const rijndael_round_keys* restrict fixed_key,
	const block_secpar* restrict prev_level, block_secpar* restrict next_level)
{
	ggm_cipher_round_keys round_keys[CHUNK_SIZE];

	size_t first_part = (n < CHUNK_SIZE / 2) ? n : CHUNK_SIZE / 2;
	expand_partial_chunk(first_part, fixed_key, &round_keys[0], &prev_level[0], &next_level[0]);
	size_t second_part = n - first_part;

	if (second_part > 0)
		expand_partial_chunk(second_part, fixed_key, &round_keys[first_part],
		                     &prev_level[first_part], &next_level[2 * first_part]);

	static_assert((2 * sizeof(block_secpar)) % sizeof(ggm_cipher_block) == 0);
	if (sizeof(block_secpar) % sizeof(ggm_cipher_block) != 0)
	{
		// Get last block of output from both parts.

		ggm_cipher_block cipher_output[CHUNK_SIZE];
		block_secpar keys[CHUNK_SIZE];
		memcpy(keys, prev_level, n * sizeof(block_secpar));
		memset(keys + n, 0, (CHUNK_SIZE - n) * sizeof(block_secpar));

		size_t j = (2 * sizeof(block_secpar)) / sizeof(ggm_cipher_block) - 1;
		prg_eval(j, round_keys, fixed_key, keys, cipher_output);
		for (size_t k = 0; k < CHUNK_SIZE; ++k)
			memcpy(((ggm_cipher_block*) &next_level[2 * k]) + j,
			       &cipher_output[k], sizeof(ggm_cipher_block));
	}
}

// Allow n to be hardcoded by the compiler into expand_level:
static void expand_level_n_chunk_size(
	const rijndael_round_keys* restrict fixed_key,
	const block_secpar* restrict prev_level, block_secpar* restrict next_level)
{
	expand_level(CHUNK_SIZE, fixed_key, prev_level, next_level);
}
static void expand_level_n_remainder(
	const rijndael_round_keys* restrict fixed_key,
	const block_secpar* restrict prev_level, block_secpar* restrict next_level)
{
	expand_level((2 * BITS_PER_WITNESS) % CHUNK_SIZE, fixed_key, prev_level, next_level);
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
			expand_level_n_remainder(fixed_key, &forest[i], &forest[FIRST_CHILD(i)]); \
		else \
			expand_level_n_chunk_size(fixed_key, &forest[i], &forest[FIRST_CHILD(i)]); \
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

static void expand_tree(
	const rijndael_round_keys* restrict fixed_key, block_secpar* restrict forest,
	unsigned int levels_to_expand, size_t index,
	block_secpar* restrict leaves, block_2secpar* restrict hashed_leaves)
{
	for (size_t leaf = 0; leaf < (1 << levels_to_expand); ++leaf)
	{
		unsigned int generations_from_ancestor = tzcnt(leaf | (1 << (levels_to_expand - 1))) + 1;
		unsigned int ancestor_level = levels_to_expand - generations_from_ancestor;

		size_t ancestor =
			BITS_PER_WITNESS * ((CHUNK_SIZE << ancestor_level) - 2) +
			CHUNK_SIZE * (leaf >> generations_from_ancestor);

		for (int i = generations_from_ancestor - 1; i >= 0; --i)
		{
			size_t child = FIRST_CHILD(ancestor) + CHUNK_SIZE * ((leaf >> i) & 1);
			expand_level_n_chunk_size(fixed_key, &forest[ancestor], &forest[child]);
			ancestor = child;
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
		expand_tree(fixed_key, forest, depth - current_depth,
		            first_node + i * CHUNK_SIZE, leaves, hashed_leaves);
		leaves += (1 << depth);
		hashed_leaves += (1 << depth);
	}
}
