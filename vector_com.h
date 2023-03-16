#ifndef VECTOR_COM_H
#define VECTOR_COM_H

#include "config.h"
#include "aes.h"
#include "block.h"
#include "vole_params.h"
#include "random_oracle.h"

#define VECTOR_COMMIT_LEAVES ((VOLES_MIN_K << VOLE_MIN_K) + (VOLES_MAX_K << VOLE_MAX_K))
#define VECTOR_OPEN_BITS (SECURITY_PARAM * SECURITY_PARAM + 2 * SECURITY_PARAM * BITS_PER_WITNESS)
#define VECTOR_OPEN_SIZE (VECTCOM_OPEN_BITS / 8)

// roots is a random vector of BITS_PER_WITNESS blocks. leaves and hashed_leaves must each be
// VECTCOM_LEAVES blocks long. tree must be 2 * VECTCOM_LEAVES - BITS_PER_WITNESS blocks long.
// leaves will be permuted according to TODO.
void vector_commit(const block_secpar* roots, block_secpar* trees, block_secpar* leaves, block_2secpar* hashed_leaves);

// Using decommitment data from vector_commit, open at delta. opening must be VECTCOM_OPEN_SIZE
// bytes long. leaves will be permuted according to TODO.
void vector_open(const block_secpar* trees, const block_2secpar* hashed_leaves, block_secpar delta, unsigned char* opening);

// Given an opening, get all but one of the leaves and all of the hashed leaves. The hashed_leaves
// must be verified against the output from vector_commit. leaves will be permuted according to TODO.
void vector_verify(const unsigned char* opening, block_secpar delta, block_secpar* leaves, block_2secpar* hashed_leaves);

#endif
