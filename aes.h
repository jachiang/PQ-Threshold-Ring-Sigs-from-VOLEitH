// Outside header guard to handle mutual inclusion.
#include "config.h"
#include "vole_params.h"

#ifndef AES_H
#define AES_H

#include "block.h"
#if SECURITY_PARAM == 128
#define AES_ROUNDS 10
#elif SECURITY_PARAM == 192
#define AES_ROUNDS 12
#elif SECURITY_PARAM == 256
#define AES_ROUNDS 14
#endif

#define RIJNDAEL192_ROUNDS 12
#define RIJNDAEL256_ROUNDS 14

// Number of AES blocks to run in parallel, for maximum performance.
#define AES_PREFERRED_WIDTH (1 << AES_PREFERRED_WIDTH_SHIFT)

// Number of Rijndael256 blocks to run in parallel, for maximum performance.
#define RIJNDAEL256_PREFERRED_WIDTH (1 << RIJNDAEL256_PREFERRED_WIDTH_SHIFT)

#define FIXED_KEY_PREFERRED_WIDTH (1 << FIXED_KEY_PREFERRED_WIDTH_SHIFT)

extern unsigned char aes_round_constants[];

#include "aes_impl.h"

// Interface defined by aes_impl.h:

// typedef /**/ aes_round_keys;
// typedef /**/ rijndael192_round_keys;
// typedef /**/ rijndael256_round_keys;
//
// #define AES_PREFERRED_WIDTH_SHIFT /**/
// #define RIJNDAEL256_PREFERRED_WIDTH_SHIFT /**/

inline void aes_keygen(aes_round_keys* aes, block_secpar key) {}
inline void rijndael192_keygen(rijndael192_round_keys* rijndael, block192 key) {}
inline void rijndael256_keygen(rijndael256_round_keys* rijndael, block256 key) {}

// Apply 1 round of the cipher, writing the state after the SBox into after_sbox, and writing the
// new state back into state. round is the index of the round key to use, so it should start from
// one.
inline void aes_round_function(const aes_round_keys* aes, block128* state, block128* after_sbox, int round);
inline void rijndael192_round_function(const rijndael192_round_keys* aes, block192* state, block192* after_sbox, int round) {}
inline void rijndael256_round_function(const rijndael256_round_keys* aes, block256* state, block256* after_sbox, int round) {}
// TODO

// Run AES key schedule on num_keys keys, the generate num_blocks block128s of output from each.
// Each key has it's own iv, which gets baked into the round keys. Outputs from the same key are
// grouped together in output.
inline void aes_keygen_ctr(
	aes_round_keys* aeses, const block_secpar* keys, const block128* ivs,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block128* output) {}
// TODO

// Given num_keys AES keys, generate num_blocks block128s of output from each, starting at
// counter. Outputs from the same key are grouped together in output.
inline void aes_ctr(
	const aes_round_keys* aeses,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block128* output);

// Given num_keys Even-Mansour keys, generate num_blocks block_secpars of output from each in CTR
// mode, starting at counter.
inline void aes_fixed_key_ctr(
	const aes_round_keys* fixed_key, const block128* keys,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block128* output) {}
inline void rijndael192_fixed_key_ctr(
	const rijndael192_round_keys* fixed_key, const block192* keys,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block192* output) {}
inline void rijndael256_fixed_key_ctr(
	const rijndael256_round_keys* fixed_key, const block256* keys,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block256* output) {}
// TODO

// Same, but for block size = security parameter.
#if SECURITY_PARAM == 128

#define FIXED_KEY_PREFERRED_WIDTH_SHIFT AES_PREFERRED_WIDTH_SHIFT
typedef aes_round_keys rijndael_round_keys;
inline void rijndael_keygen(rijndael_round_keys* round_keys, block_secpar key)
{
	aes_keygen(round_keys, key);
}
inline void rijndael_fixed_key_ctr(
	const rijndael_round_keys* fixed_key, const block_secpar* keys,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block_secpar* output)
{
	aes_fixed_key_ctr(fixed_key, keys, num_keys, num_blocks, counter, output);
}

#elif SECURITY_PARAM == 192

typedef rijndael192_round_keys rijndael_round_keys;
inline void rijndael_keygen(rijndael_round_keys* round_keys, block_secpar key)
{
	rijndael192_keygen(round_keys, key);
}
inline void rijndael_fixed_key_ctr(
	const rijndael_round_keys* fixed_key, const block_secpar* keys,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block_secpar* output)
{
	rijndael192_fixed_key_ctr(fixed_key, keys, num_keys, num_blocks, counter, output);
}

#elif SECURITY_PARAM == 256

#define FIXED_KEY_PREFERRED_WIDTH_SHIFT RIJNDAEL256_PREFERRED_WIDTH_SHIFT
typedef rijndael256_round_keys rijndael_round_keys;
inline void rijndael_keygen(rijndael_round_keys* round_keys, block_secpar key)
{
	rijndael256_keygen(round_keys, key);
}
inline void rijndael_fixed_key_ctr(
	const rijndael_round_keys* fixed_key, const block_secpar* keys,
	size_t num_keys, uint32_t num_blocks, uint32_t counter, block_secpar* output)
{
	rijndael256_fixed_key_ctr(fixed_key, keys, num_keys, num_blocks, counter, output);
}

#endif

#endif
