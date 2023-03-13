#ifndef SMALL_VOLE_H
#define SMALL_VOLE_H

#include "block.h"

// The homomorphic commitments use the small field VOLE with a mix of two values of k: VOLE_MIN_K
// and VOLE_MAX_K. k is the number of bits of Delta input to a single VOLE.
#define VOLE_MIN_K (SECURITY_PARAM / BITS_PER_WITNESS)
#define VOLE_MAX_K ((SECURITY_PARAM + BITS_PER_WITNESS - 1) / BITS_PER_WITNESS)

// How many times to duplicate each PRG key (for easier vectorized access.)
#if defined(PRG_AES_CTR)
#define VOLE_KEY_DUPS AES_VECTOR_WIDTH
#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
#define VOLE_KEY_DUPS 1
#endif

typedef struct
{
	prg_key keys[VOLE_KEY_DUPS << VOLE_MAX_K];
	size_t idx;
} vole_prgs_state;

typedef struct
{
	vole_prgs_state prgs;
} vole_sender_state;

typedef struct
{
	vole_prgs_state prgs;

	// Delta, expanded so that each bit is stored in a single byte (either 0 or 0xff).
	unsigned char delta_bytes[VOLE_MAX_K];
} vole_receiver_state;

// Given the chosen VOLE input u, generate the VOLE correlation v and a correction c to send to the
// receiver. u must be FAEST_WITNESS_BITS bits long, and c must be VOLE_ROWS bits long. v is stored
// in column-major order, with columns packed tightly (after being padded to a whole number of
// block_preferreds).
void generate_sender_min_k(vole_sender_state* state, const block_preferred* u, block_preferred* v, size_t stride, block_preferred* c)
void generate_sender_max_k(vole_sender_state* state, const block_preferred* u, block_preferred* v, size_t stride, block_preferred* c)

// Given the correction c, generate the VOLE correlation q.  q is stored in column-major order, with
// columns separated by stride blocks.
void generate_receiver_min_k(vole_receiver_state* state, const block_preferred* c, block_preferred* q, size_t stride);
void generate_receiver_max_k(vole_receiver_state* state, const block_preferred* c, block_preferred* q, size_t stride);

#endif
