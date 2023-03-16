#ifndef SMALL_VOLE_H
#define SMALL_VOLE_H

#include "config.h"
#include "block.h"
#include "aes.h"
#include "vole_params.h"

// Given 2**k PRG keys and the chosen VOLE input u, generate the VOLE correlation v and a correction
// c to send to the receiver. u and c must be VOLE_ROWS bits long. v is stored in column-major
// order, with columns packed tightly (after being padded to a whole number of vole_blocks).
// k must be at least VOLE_WIDTH_SHIFT. fixed_key is only used for PRGs based on fixed-key
// Rijndael. Input must by permuted according to TODO.
void generate_sender(
	unsigned int k, const block_secpar* restrict keys, const rijndael_round_keys* restrict fixed_key,
	const vole_block* restrict u, vole_block* restrict v, vole_block* restrict c);

// Given 2**k PRG keys, the secret delta, and the correction string c, generate the VOLE correlation
// q. c must be VOLE_ROWS bits long. q is stored in column-major order, with columns packed tightly
// (after being padded to a whole number of vole_blocks). A k-bit delta is represented as k bytes,
// with each byte being either 0 or 0xff. k must be at least VOLE_WIDTH_SHIFT. fixed_key is only
// used for PRGs based on fixed-key Rijndael. Input must by permuted according to TODO.
void generate_receiver(
	unsigned int k, const block_secpar* restrict keys, const rijndael_round_keys* restrict fixed_key,
	const vole_block* restrict c, vole_block* restrict q,
	const unsigned char* restrict delta);

#endif
