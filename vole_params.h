#ifndef VOLE_PARMS_H
#define VOLE_PARMS_H

#include <assert.h>

#include "block.h"
#include "prgs.h"
#include "owf_proof.h"
#include "vole_check.h"

// The homomorphic commitments use small field VOLE with a mix of two values of k: VOLE_MIN_K and
// VOLE_MAX_K. k is the number of bits of Delta input to a single VOLE.

#define NONZERO_BITS_IN_CHALLENGE_3 (SECURITY_PARAM - ZERO_BITS_IN_CHALLENGE_3)

#define VOLE_MIN_K (NONZERO_BITS_IN_CHALLENGE_3  / BITS_PER_WITNESS)
#define VOLE_MAX_K ((NONZERO_BITS_IN_CHALLENGE_3  + BITS_PER_WITNESS - 1) / BITS_PER_WITNESS)

// Number of VOLEs that use VOLE_MIN_K and VOLES_MAX_K.
#define VOLES_MIN_K (BITS_PER_WITNESS - VOLES_MAX_K)
#define VOLES_MAX_K (NONZERO_BITS_IN_CHALLENGE_3  % BITS_PER_WITNESS)

#if (FAEST_RING_HOTVECTOR_DIM == 1)
#define FAEST_RING_PROOF_ELEMS (2)
#elif  (FAEST_RING_HOTVECTOR_DIM == 2)
#define FAEST_RING_PROOF_ELEMS (3)
#elif  (FAEST_RING_HOTVECTOR_DIM == 4)
#define FAEST_RING_PROOF_ELEMS (5)
#endif

static_assert(WITNESS_BITS % 8 == 0, "");
#define WITNESS_BLOCKS ((WITNESS_BITS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#define TAGGED_WITNESS_BLOCKS ((TAGGED_WITNESS_BITS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#define RING_WITNESS_BLOCKS ((RING_WITNESS_BITS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#if defined(OWF_AES_CTR)
	#define CBC_TAGGED_RING_WITNESS_BLOCKS ((CBC_TAGGED_RING_WITNESS_BITS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#endif
// TODO: Deprecate.
#define TAGGED_RING_WITNESS_BLOCKS ((TAGGED_RING_WITNESS_BITS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))

#define QUICKSILVER_ROW_PAD_TO \
	(128 * VOLE_BLOCK > TRANSPOSE_BITS_ROWS ? 128 * VOLE_BLOCK : TRANSPOSE_BITS_ROWS)

#define QUICKSILVER_ROWS (WITNESS_BITS + SECURITY_PARAM)
#define QUICKSILVER_ROWS_PADDED \
	((QUICKSILVER_ROWS + QUICKSILVER_ROW_PAD_TO - 1) / QUICKSILVER_ROW_PAD_TO) * QUICKSILVER_ROW_PAD_TO

#define QUICKSILVER_TAGGED_ROWS (TAGGED_WITNESS_BITS + SECURITY_PARAM)
#define QUICKSILVER_TAGGED_ROWS_PADDED \
	((QUICKSILVER_TAGGED_ROWS + QUICKSILVER_ROW_PAD_TO - 1) / QUICKSILVER_ROW_PAD_TO) * QUICKSILVER_ROW_PAD_TO

#define QUICKSILVER_RING_ROWS (RING_WITNESS_BITS + FAEST_RING_PROOF_ELEMS * SECURITY_PARAM) // Updated for higher degree QS mask.
#define QUICKSILVER_RING_ROWS_PADDED \
	((QUICKSILVER_RING_ROWS + QUICKSILVER_ROW_PAD_TO - 1) / QUICKSILVER_ROW_PAD_TO) * QUICKSILVER_ROW_PAD_TO

#if defined(OWF_AES_CTR)
#define QUICKSILVER_CBC_TAGGED_RING_ROWS (CBC_TAGGED_RING_WITNESS_BITS + FAEST_RING_PROOF_ELEMS * SECURITY_PARAM) // Updated for higher degree QS mask.
#define QUICKSILVER_CBC_TAGGED_RING_ROWS_PADDED \
	((QUICKSILVER_CBC_TAGGED_RING_ROWS + QUICKSILVER_ROW_PAD_TO - 1) / QUICKSILVER_ROW_PAD_TO) * QUICKSILVER_ROW_PAD_TO
#endif

// TODO: Deprecate.
#define QUICKSILVER_TAGGED_RING_ROWS (TAGGED_RING_WITNESS_BITS + FAEST_RING_PROOF_ELEMS * SECURITY_PARAM) // Updated for higher degree QS mask.
#define QUICKSILVER_TAGGED_RING_ROWS_PADDED \
	((QUICKSILVER_TAGGED_RING_ROWS + QUICKSILVER_ROW_PAD_TO - 1) / QUICKSILVER_ROW_PAD_TO) * QUICKSILVER_ROW_PAD_TO

#define VOLE_ROWS (QUICKSILVER_ROWS + VOLE_CHECK_HASH_BYTES * 8)
#define VOLE_TAGGED_ROWS (QUICKSILVER_TAGGED_ROWS + VOLE_CHECK_HASH_BYTES * 8)
#define VOLE_RING_ROWS (QUICKSILVER_RING_ROWS + VOLE_CHECK_HASH_BYTES * 8)
#define VOLE_CBC_TAGGED_RING_ROWS (QUICKSILVER_CBC_TAGGED_RING_ROWS + VOLE_CHECK_HASH_BYTES * 8)
// TODO: Deprecate.
#define VOLE_TAGGED_RING_ROWS (QUICKSILVER_TAGGED_RING_ROWS + VOLE_CHECK_HASH_BYTES * 8)

#define VOLE_COL_BLOCKS ((VOLE_ROWS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#define VOLE_COL_STRIDE (VOLE_COL_BLOCKS * 16 * VOLE_BLOCK)
#define VOLE_ROWS_PADDED (VOLE_COL_BLOCKS * 128 * VOLE_BLOCK)

#define VOLE_TAGGED_COL_BLOCKS ((VOLE_TAGGED_ROWS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#define VOLE_TAGGED_COL_STRIDE (VOLE_TAGGED_COL_BLOCKS * 16 * VOLE_BLOCK)
#define VOLE_TAGGED_ROWS_PADDED (VOLE_TAGGED_COL_BLOCKS * 128 * VOLE_BLOCK)

#define VOLE_RING_COL_BLOCKS ((VOLE_RING_ROWS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#define VOLE_RING_COL_STRIDE (VOLE_RING_COL_BLOCKS * 16 * VOLE_BLOCK)
#define VOLE_RING_ROWS_PADDED (VOLE_RING_COL_BLOCKS * 128 * VOLE_BLOCK)

#if defined(OWF_AES_CTR)
#define VOLE_CBC_TAGGED_RING_COL_BLOCKS ((VOLE_CBC_TAGGED_RING_ROWS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#define VOLE_CBC_TAGGED_RING_COL_STRIDE (VOLE_CBC_TAGGED_RING_COL_BLOCKS * 16 * VOLE_BLOCK)
#define VOLE_CBC_TAGGED_RING_ROWS_PADDED (VOLE_CBC_TAGGED_RING_COL_BLOCKS * 128 * VOLE_BLOCK)
#endif

// TODO: Deprecate.
#define VOLE_TAGGED_RING_COL_BLOCKS ((VOLE_TAGGED_RING_ROWS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK))
#define VOLE_TAGGED_RING_COL_STRIDE (VOLE_TAGGED_RING_COL_BLOCKS * 16 * VOLE_BLOCK)
#define VOLE_TAGGED_RING_ROWS_PADDED (VOLE_TAGGED_RING_COL_BLOCKS * 128 * VOLE_BLOCK)

#if defined(PRG_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 256
#define PRG_VOLE_BLOCK_SIZE_SHIFT 1
#else
#define PRG_VOLE_BLOCK_SIZE_SHIFT 0
#endif

// Number of block128s in a prg_vole_block.
#define PRG_VOLE_BLOCK_SIZE (1 << PRG_VOLE_BLOCK_SIZE_SHIFT)
static_assert(PRG_VOLE_BLOCK_SIZE * 16 == sizeof(prg_vole_block), "a `prg_vole_block` must be 16 * PRG_VOLE_BLOCK_SIZE");

// Number of prg_vole_block in a vole_block.
#define PRG_VOLE_BLOCKS (1 << PRG_VOLE_BLOCKS_SHIFT)
#define PRG_VOLE_BLOCKS_SHIFT (VOLE_BLOCK_SHIFT - PRG_VOLE_BLOCK_SIZE_SHIFT)

// VOLE is performed in chunks of VOLE_WIDTH keys, with each column consisting of 1
// vole_block.
#define VOLE_WIDTH (1 << VOLE_WIDTH_SHIFT)
#define VOLE_WIDTH_SHIFT (AES_PREFERRED_WIDTH_SHIFT - PRG_VOLE_BLOCKS_SHIFT)

// Everything aes.h needs from vole_params.h comes before.
#include "aes.h"

#endif
