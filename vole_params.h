#ifndef VOLE_PARMS_H
#define VOLE_PARMS_H

#include "block.h"

// The homomorphic commitments use small field VOLE with a mix of two values of k: VOLE_MIN_K and
// VOLE_MAX_K. k is the number of bits of Delta input to a single VOLE.
#define VOLE_MIN_K (SECURITY_PARAM / BITS_PER_WITNESS)
#define VOLE_MAX_K ((SECURITY_PARAM + BITS_PER_WITNESS - 1) / BITS_PER_WITNESS)

// Number of VOLEs that use VOLE_MIN_K and VOLES_MAX_K.
#define VOLES_MIN_K (BITS_PER_WITNESS - VOLES_MAX_K)
#define VOLES_MAX_K (SECURITY_PARAM % BITS_PER_WITNESS)

#define VOLE_ROWS 1600 // TODO

#if defined(PRG_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 256
#define VOLE_CIPHER_BLOCK_SHIFT 1
#else
#define VOLE_CIPHER_BLOCK_SHIFT 0
#endif

// Number of block128s in a vole_cipher_block.
#define VOLE_CIPHER_BLOCK (1 << VOLE_CIPHER_BLOCK_SHIFT)

// Number of vole_cipher_block in a vole_block.
#define VOLE_CIPHER_BLOCKS (1 << VOLE_CIPHER_BLOCKS_SHIFT)
#define VOLE_CIPHER_BLOCKS_SHIFT (VOLE_BLOCK_SHIFT - VOLE_CIPHER_BLOCK_SHIFT)

// VOLE is performed in chunks of VOLE_WIDTH keys, with each column consisting of 1
// vole_block.
#define VOLE_WIDTH (1 << VOLE_WIDTH_SHIFT)
#define VOLE_WIDTH_SHIFT (AES_PREFERRED_WIDTH_SHIFT - VOLE_CIPHER_BLOCKS_SHIFT)

// Everything aes.h needs from vole_params.h comes before.
#include "aes.h"


#if defined(PRG_AES_CTR)
// Block of the cipher used for the small field VOLE.
typedef block128 vole_cipher_block;
typedef aes_round_keys vole_cipher_round_keys;

#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
typedef block_secpar vole_cipher_block;
typedef rijndael_round_keys vole_cipher_round_keys;

#if SECURITY_PARAM == 192
#error Unsupported PRG configuration.
#endif

#else
#error PRG for small field VOLE is unspecified.
#endif

#endif
