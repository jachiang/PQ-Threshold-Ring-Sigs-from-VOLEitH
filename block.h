#ifndef BLOCK_H
#define BLOCK_H

#include "block_impl.h"

// Interface defined by block_impl.h

// typedef /**/ block128;
// typedef /**/ block256;
//
// // Size of the largest supported vector register (at least block128).
// typedef /**/ block_preferred;
//
// #define BLOCK_PREFERRED_LEN_SHIFT /**/

// Number of block128s in a block_preferred
#define BLOCK_PREFERRED_LEN (1 << BLOCK_PREFERRED_LEN_SHIFT)

inline block128 block128_xor(block128 x, block128 y);
inline block256 block256_xor(block256 x, block256 y);
inline block_preferred block_preferred_xor(block_preferred x, block_preferred y);

#endif
