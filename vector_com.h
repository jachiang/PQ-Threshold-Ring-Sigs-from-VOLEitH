#ifndef VECTOR_COM_H
#define VECTOR_COM_H

#include "config.h"
#include "aes.h"
#include "block.h"
#include "vole_params.h"
#include "random_oracle.h"

#define VECTOR_COMMIT_LEAVES ((VOLES_MIN_K << VOLE_MIN_K) + (VOLES_MAX_K << VOLE_MAX_K))
#define VECTOR_COMMIT_NODES (2 * (VECTOR_COMMIT_LEAVES - BITS_PER_WITNESS))
#define VECTOR_OPEN_BITS (SECURITY_PARAM * SECURITY_PARAM + 2 * SECURITY_PARAM * BITS_PER_WITNESS)
#define VECTOR_OPEN_SIZE (VECTCOM_OPEN_BITS / 8)

// roots is a random vector of 2 * BITS_PER_WITNESS blocks. leaves and hashed_leaves must each be
// VECTOR_COMMIT_LEAVES blocks long. forest must be VECTOR_COMMIT_NODES blocks long. leaves (but not
// hashed_leaves) will be permuted according to vole_permute_key_index. fixed_key is only used for
// PRGs based on fixed-key Rijndael.
void vector_commit(
	const block_secpar* restrict roots, const rijndael_round_keys* restrict fixed_key,
	block_secpar* restrict forest, block_secpar* restrict leaves,
	block_2secpar* restrict hashed_leaves);

// Using decommitment data from vector_commit, open at delta. opening must be VECTCOM_OPEN_SIZE
// bytes long.
void vector_open(
	const block_secpar* restrict forest, const block_2secpar* restrict hashed_leaves,
	block_secpar delta, unsigned char* restrict opening);

// Given an opening, get all but one of the leaves and all of the hashed leaves. The hashed_leaves
// must be verified against the output from vector_commit. leaves will be permuted according to
// TODO. fixed_key is only used for PRGs based on fixed-key Rijndael.
void vector_verify(
	const unsigned char* restrict opening, const rijndael_round_keys* restrict fixed_key,
	block_secpar delta, block_secpar* restrict leaves, block_2secpar* restrict hashed_leaves);

#endif
