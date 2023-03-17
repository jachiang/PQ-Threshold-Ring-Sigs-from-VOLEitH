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


#if defined(PRG_AES_CTR)
// Block of the cipher used for the small field VOLE.
#define VOLE_CIPHER_BLOCK_SHIFT 0
typedef block128 vole_cipher_block;
typedef aes_round_keys vole_cipher_round_keys;
inline vole_cipher_block vole_cipher_block_xor(vole_cipher_block x, vole_cipher_block y) { return block128_xor(x, y); }
inline vole_cipher_block vole_cipher_block_set_low64(uint64_t x) { return block128_set_low64(x); }

#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
#define VOLE_CIPHER_BLOCK_SHIFT 1
typedef block_secpar vole_cipher_block;
typedef rijndael_round_keys vole_cipher_round_keys;
inline vole_cipher_block vole_cipher_block_xor(vole_cipher_block x, vole_cipher_block y) { return block_secpar_xor(x, y); }
inline vole_cipher_block vole_cipher_block_set_low64(uint64_t x) { return block_secpar_set_low64(x); }

#if SECURITY_PARAM == 192
#error Unsupported PRG configuration.
#endif

#else
#error PRG for small field VOLE is unspecified.
#endif

// Number of block128s in a vole_cipher_block.
#define VOLE_CIPHER_BLOCK (1 << VOLE_CIPHER_BLOCK_SHIFT)

// Number of vole_cipher_block in a vole_block.
#define VOLE_CIPHER_BLOCKS (1 << VOLE_CIPHER_BLOCKS_SHIFT)
#define VOLE_CIPHER_BLOCKS_SHIFT (VOLE_BLOCK_SHIFT - VOLE_CIPHER_BLOCK_SHIFT)

// VOLE is performed in chunks of VOLE_WIDTH columns, with each column consisting of 1
// vole_block.
#define VOLE_WIDTH (1 << VOLE_WIDTH_SHIFT)
#define VOLE_WIDTH_SHIFT (AES_PREFERRED_WIDTH_SHIFT - VOLE_CIPHER_BLOCKS_SHIFT)
// TODO: What about a RIJNDAEL_PREFERRED_WIDTH?

#endif
