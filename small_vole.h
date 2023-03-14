#ifndef SMALL_VOLE_H
#define SMALL_VOLE_H

#include "block.h"

// The homomorphic commitments use the small field VOLE with a mix of two values of k: VOLE_MIN_K
// and VOLE_MAX_K. k is the number of bits of Delta input to a single VOLE.
#define VOLE_MIN_K (SECURITY_PARAM / BITS_PER_WITNESS)
#define VOLE_MAX_K ((SECURITY_PARAM + BITS_PER_WITNESS - 1) / BITS_PER_WITNESS)

// Given the PRG keys and the chosen VOLE input u, generate the VOLE correlation v and a correction
// c to send to the receiver. u and c must be VOLE_ROWS bits long. v is stored in column-major
// order, with columns packed tightly (after being padded to a whole number of block_preferreds).
// fixed_key is only used for PRGs based on fixed-key AES. Input must by permuted according to
// TODO.
void generate_sender_min_k(
	const block_secpar* restrict keys, const TODO_round_keys* restrict fixed_key,
	const block_preferred* restrict u, block_preferred* restrict v, block_preferred* restrict c);
void generate_sender_max_k(
	const block_secpar* restrict keys, const TODO_round_keys* restrict fixed_key,
	const block_preferred* restrict u, block_preferred* restrict v, block_preferred* restrict c);

// Given the correction c, generate the VOLE correlation q. The arguments are similar to
// Given the PRG keys, the secret delta, and the correction string c, generate the VOLE correlation
// q. c must be VOLE_ROWS bits long. q is stored in column-major order, with columns packed tightly
// (after being padded to a whole number of block_preferreds). A k-bit delta is represented as k
// bytes, with each byte being either 0 or 0xff. fixed_key is only used for PRGs based on fixed-key
// AES. Input must by permuted according to TODO.
void generate_receiver_min_k(
	const block_secpar* restrict keys, const TODO_round_keys* restrict fixed_key,
	const block_preferred* restrict c, block_preferred* restrict q,
	const unsigned char* restrict delta);
void generate_receiver_max_k(
	const block_secpar* restrict keys, const TODO_round_keys* restrict fixed_key,
	const block_preferred* restrict c, block_preferred* restrict q,
	const unsigned char* restrict delta);

#endif
