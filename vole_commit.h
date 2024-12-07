#ifndef VOLE_COMMIT_H
#define VOLE_COMMIT_H

#include "block.h"

#define VOLE_COMMIT_SIZE ((VOLE_ROWS / 8) * (BITS_PER_WITNESS - 1))
#define VOLE_RING_COMMIT_SIZE ((VOLE_RING_ROWS / 8) * (BITS_PER_WITNESS - 1))
#define VOLE_CBC_TAGGED_RING_COMMIT_SIZE ((VOLE_CBC_TAGGED_RING_ROWS / 8) * (BITS_PER_WITNESS - 1))
#define VOLE_TAGGED_RING_COMMIT_SIZE ((VOLE_TAGGED_RING_ROWS / 8) * (BITS_PER_WITNESS - 1)) // TODO: Deprecate.
#define VOLE_COMMIT_CHECK_SIZE (2 * SECURITY_PARAM / 8)

#if USE_IMPROVED_VECTOR_COMMITMENTS == 0
	#define FOREST_SIZE PPRF_VECTOR_COM_NODES
	#define VECTOR_COM_OPEN_SIZE PPRF_VECTOR_COM_OPEN_SIZE
#else
	#define FOREST_SIZE BATCH_VECTOR_COMMIT_NODES
	#define VECTOR_COM_OPEN_SIZE BATCH_VECTOR_OPENING_SIZE
#endif

// Run the vector commitment and the small vole protocols.
// - `forest` must be `FOREST_SIZE` blocks long.
// - `hashed_leaves` must be VECTOR_COMMIT_LEAVES blocks long.
// - `u` must be `VOLE_COL_BLOCKS` long
// - `v` must be `SECURITY_PARAM * VOLE_COL_BLOCKS` long
// - `commitment` must be `(BITS_PER_WITNESS - 1) * VOLE_ROWS / 8` long
// - `check` must be `2 * SECURITY_PARAM / 8` long
void vole_commit(
	block_secpar seed, block128 iv, block_secpar* restrict forest, block_2secpar* hashed_leaves,
	vole_block* restrict u, vole_block* restrict v,
	uint8_t* restrict commitment, uint8_t* restrict check);

// - `q` must be `SECURITY_PARAM * VOLE_COL_BLOCKS` long
// - `delta_bytes` must be `SECURITY_PARAM` long
// - `commitment` must be `(BITS_PER_WITNESS - 1) * VOLE_ROWS / 8` long
// - `check` must be `2 * SECURITY_PARAM / 8` long
// - `opening` must be `VECTOR_COM_OPEN_SIZE` long
bool vole_reconstruct(
	block128 iv, vole_block* restrict q, const uint8_t* delta_bytes,
	const uint8_t* restrict commitment, const uint8_t* restrict opening, uint8_t* restrict check);

// Run the vector commitment and the small vole protocols for ring signer.
// - `forest` must be `FOREST_SIZE` blocks long.
// - `hashed_leaves` must be VECTOR_COMMIT_LEAVES blocks long.
// - `u` must be `VOLE_RING_COL_BLOCKS` long
// - `v` must be `SECURITY_PARAM * VOLE_RING_COL_BLOCKS` long
// - `commitment` must be `(BITS_PER_WITNESS - 1) * VOLE_RING_ROWS / 8` long
// - `check` must be `2 * SECURITY_PARAM / 8` long
void vole_commit_for_ring(
	block_secpar seed, block128 iv, block_secpar* restrict forest, block_2secpar* hashed_leaves,
	vole_block* restrict u, vole_block* restrict v,
	uint8_t* restrict commitment, uint8_t* restrict check);

void vole_commit_for_tagged_ring(
	block_secpar seed, block128 iv, block_secpar* restrict forest, block_2secpar* hashed_leaves,
	vole_block* restrict u, vole_block* restrict v,
	uint8_t* restrict commitment, uint8_t* restrict check);

// - `q` must be `SECURITY_PARAM * VOLE_RING_COL_BLOCKS` long
// - `delta_bytes` must be `SECURITY_PARAM` long
// - `commitment` must be `(BITS_PER_WITNESS - 1) * VOLE_RING_ROWS / 8` long
// - `check` must be `2 * SECURITY_PARAM / 8` long
// - `opening` must be `VECTOR_COM_OPEN_SIZE` long
bool vole_reconstruct_for_ring(
	block128 iv, vole_block* restrict q, const uint8_t* delta_bytes,
	const uint8_t* restrict commitment, const uint8_t* restrict opening, uint8_t* restrict check);

bool vole_reconstruct_for_tagged_ring(
	block128 iv, vole_block* restrict q, const uint8_t* delta_bytes,
	const uint8_t* restrict commitment, const uint8_t* restrict opening, uint8_t* restrict check);

#if defined(OWF_AES_CTR)
void vole_commit_for_cbc_tagged_ring(
	block_secpar seed, block128 iv, block_secpar* restrict forest, block_2secpar* hashed_leaves,
	vole_block* restrict u, vole_block* restrict v,
	uint8_t* restrict commitment, uint8_t* restrict check);

bool vole_reconstruct_for_cbc_tagged_ring(
	block128 iv, vole_block* restrict q, const uint8_t* delta_bytes,
	const uint8_t* restrict commitment, const uint8_t* restrict opening, uint8_t* restrict check);
#endif

#endif
