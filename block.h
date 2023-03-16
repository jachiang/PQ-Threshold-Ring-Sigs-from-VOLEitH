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
// typedef /**/ block_secpar;
//
// // Block representing a chunck of a column for the small field VOLE. Used when reducing the PRG
// // outputs down to a VOLE correlation. THis will be at least as big as vole_cipher_block.
// typedef /**/ vole_block;
// #define VOLE_BLOCK_SHIFT /**/

// Number of block128s in a vole_block.
#define VOLE_BLOCK (1 << VOLE_BLOCK_SHIFT)

static_assert(sizeof(block128) == 16, "Padding in block128.");
static_assert(sizeof(block192) == 24, "Padding in block192.");
static_assert(sizeof(block256) == 32, "Padding in block256.");

#if SECURITY_PARAM == 128
#define BLOCK_SECPAR_LEN_SHIFT 0
#elif SECURITY_PARAM == 256
#define BLOCK_SECPAR_LEN_SHIFT 1
#endif

// Number of block128s in a block_secpar, assuming that this is a whole number.
#define BLOCK_SECPAR_LEN (1 << BLOCK_SECPAR_LEN_SHIFT)

inline block128 block128_xor(block128 x, block128 y);
inline block256 block256_xor(block256 x, block256 y);
inline block_secpar block_secpar_xor(block_secpar x, block_secpar y);

inline block128 block128_set_low64(uint64_t x);
inline block256 block256_set_low64(uint64_t x);
inline block_secpar block_secpar_set_low64(uint64_t x);

inline block256 block256_set_128(block128 x0, block128 x1);

#endif
