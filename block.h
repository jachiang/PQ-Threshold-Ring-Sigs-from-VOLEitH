#ifndef BLOCK_H
#define BLOCK_H

#include <assert.h>
#include "inttypes.h"

typedef struct
{
	uint64_t data[3];
} block192;

inline block192 block192_xor(block192 x, block192 y)
{
	// Plain c version for now at least. Hopefully it will be autovectorized.
	block192 out;
	out.data[0] = x.data[0] ^ y.data[0];
	out.data[1] = x.data[1] ^ y.data[1];
	out.data[2] = x.data[2] ^ y.data[2];
	return out;
}

inline block192 block192_set_low64(uint64_t x)
{
	block192 out = {x, 0, 0};
	return out;
}

#include "block_impl.h"

// Interface defined by block_impl.h

// typedef /**/ block128;
// typedef /**/ block192;
// typedef /**/ block256;
//
// // Size of the largest supported vector register (at least block128).
// typedef /**/ block_preferred;
//
// typedef /**/ block_secpar;
//
// #define BLOCK_PREFERRED_LEN_SHIFT /**/

// Number of block128s in a block_preferred
#define BLOCK_PREFERRED_LEN (1 << BLOCK_PREFERRED_LEN_SHIFT)

// TODO: I think these things need to be more specialized. Instead of "vector size", which may be
// too small for somethings, I think it should just be 1 block typedef for every different kind of
// block size that may occur in the program. Like cipher_block in small_vole.h.

static_assert(sizeof(block128) == 16, "Padding in block128.");
static_assert(sizeof(block192) == 24, "Padding in block192.");
static_assert(sizeof(block256) == 32, "Padding in block256.");
static_assert(sizeof(block_preferred) == BLOCK_PREFERRED_LEN * 16, "Padding in block_preferred.");

inline block128 block128_xor(block128 x, block128 y);
inline block256 block256_xor(block256 x, block256 y);
inline block_preferred block_preferred_xor(block_preferred x, block_preferred y);
inline block_secpar block_secpar_xor(block_secpar x, block_secpar y);

inline block128 block128_set_low64(uint64_t x);
inline block256 block256_set_low64(uint64_t x);
inline block_secpar block_secpar_set_low64(uint64_t x);
inline block_preferred block_preferred_set_low64(uint64_t x);

inline block256 block256_set_128(block128 x0, block128 x1);

#endif
