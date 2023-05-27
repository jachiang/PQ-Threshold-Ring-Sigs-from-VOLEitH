#include "vole_commit.h"

#include <stdalign.h>
#include <stdlib.h>
#include "small_vole.h"
#include "vector_com.h"
#include "hash.h"

static void hash_hashed_leaves_all_same_size(
	hash_state* commitment_hasher, block_2secpar* hashed_leaves, size_t num_trees, size_t num_leaves)
{
	for (size_t i = 0; (i + 4) <= num_trees; i += 4)
	{
		const void* to_hash[4];
		for (size_t j = 0; j < 4; ++j, hashed_leaves += num_leaves)
			to_hash[j] = hashed_leaves;

		block_2secpar leaves_hashes[4];
		hash_state_x4 leaves_hasher;
		hash_init_x4(&leaves_hasher);
		hash_update_x4(&leaves_hasher, to_hash, num_leaves * sizeof(block_2secpar));
		hash_final_x4_4(&leaves_hasher, &leaves_hashes[0], &leaves_hashes[1],
		                &leaves_hashes[2], &leaves_hashes[3], sizeof(leaves_hashes[0]));

		hash_update(commitment_hasher, &leaves_hashes[0], sizeof(leaves_hashes));
	}

	for (size_t i = num_trees - (num_trees % 4); i < num_trees; ++i, hashed_leaves += num_leaves)
	{
		block_2secpar leaves_hash;
		hash_state leaves_hasher;
		hash_init(&leaves_hasher);
		hash_update(&leaves_hasher, hashed_leaves, num_leaves * sizeof(block_2secpar));
		hash_final(&leaves_hasher, &leaves_hash, sizeof(leaves_hash));

		hash_update(commitment_hasher, &leaves_hash, sizeof(leaves_hash));
	}
}

static size_t hash_hashed_leaves(block_2secpar* hashed_leaves, uint8_t* restrict commitment)
{
	hash_state commitment_hasher;
	hash_init(&commitment_hasher);
	hash_hashed_leaves_all_same_size(
		&commitment_hasher, hashed_leaves, VOLES_MAX_K, (size_t) 1 << VOLE_MAX_K);
	hash_hashed_leaves_all_same_size(
		&commitment_hasher, hashed_leaves + ((size_t) VOLES_MAX_K << VOLE_MAX_K),
		VOLES_MIN_K, (size_t) 1 << VOLE_MIN_K);
	hash_final(&commitment_hasher, commitment, 2 * SECURITY_PARAM / 8);
	return 2 * SECURITY_PARAM / 8;
}

size_t vole_commit(
	block_secpar seed, block_secpar* restrict forest,
	vole_block* restrict u, vole_block* restrict v, uint8_t* restrict commitment)
{
	block_secpar* leaves =
		aligned_alloc(alignof(block_secpar), VECTOR_COMMIT_LEAVES * sizeof(block_secpar));
	block_2secpar* hashed_leaves =
		aligned_alloc(alignof(block_2secpar), VECTOR_COMMIT_LEAVES * sizeof(block_2secpar));

	vector_commit(seed, forest, leaves, hashed_leaves);

	uint8_t* com_iter = commitment;
	com_iter += hash_hashed_leaves(hashed_leaves, com_iter);
	free(hashed_leaves);

    block_secpar fixed_key_iv = block_secpar_set_zero(); // TODO
	prg_vole_fixed_key fixed_key;
    vole_fixed_key_init(&fixed_key, fixed_key_iv);

	block_2secpar correction[VOLE_COL_BLOCKS];
	block_secpar* leaves_iter = leaves;
	vole_block* v_iter = v;
	for (size_t i = 0; i < BITS_PER_WITNESS; ++i)
	{
		unsigned int k = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
		if (!i)
			vole_sender(k, leaves_iter, &fixed_key, NULL, v_iter, u);
		else
		{
			vole_sender(k, leaves_iter, &fixed_key, u, v_iter, correction);
			memcpy(com_iter, correction, VOLE_ROWS / 8);
			com_iter += VOLE_ROWS / 8;
		}

		leaves_iter += (size_t) 1 << k;
		v_iter += VOLE_COL_BLOCKS * k;
	}

	free(leaves);
	return com_iter - commitment;
}
