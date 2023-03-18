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

#include "aes_impl.h"

// Interface defined by aes_impl.h

// typedef /**/ aes_round_keys;
// typedef /**/ rijndael192_round_keys;
// typedef /**/ rijndael256_round_keys;
//
// #define AES_PREFERRED_WIDTH_SHIFT /**/
// #define RIJNDAEL256_PREFERRED_WIDTH_SHIFT /**/

// Number of AES blocks to run in parallel, for maximum performance.
#define AES_PREFERRED_WIDTH (1 << AES_PREFERRED_WIDTH_SHIFT)

// Number of Rijndael256 blocks to run in parallel, for maximum performance.
#define RIJNDAEL256_PREFERRED_WIDTH (1 << RIJNDAEL256_PREFERRED_WIDTH_SHIFT)

#define FIXED_KEY_PREFERRED_WIDTH (1 << FIXED_KEY_PREFERRED_WIDTH_SHIFT)

inline void aes_keygen(aes_round_keys* aes, block_secpar key);
inline void rijndael192_keygen(rijndael192_round_keys* rijndael, block192 key);
inline void rijndael256_keygen(rijndael256_round_keys* rijndael, block256 key);

inline void aes_round_function(const aes_round_keys* aes, block128* state, block128* after_sbox, int round);
inline void rijndael192_round_function(const rijndael192_round_keys* aes, block192* state, block192* after_sbox, int round);
inline void rijndael256_round_function(const rijndael256_round_keys* aes, block256* state, block256* after_sbox, int round);

// Run AES key schedule on VOLE_WIDTH keys, then generate VOLE_BLOCK block128s of output from each in
// CTR mode, starting at counter.
inline void aes_keygen_ctr_vole(aes_round_keys* aeses, const block_secpar* keys, size_t counter, block128* output);

// Run AES key schedule on AES_PREFERRED_WIDTH/2 keys, then generate 2 blocks of output from each in
// CTR mode, starting at counter.
inline void aes_keygen_ctr_x2(aes_round_keys* aeses, const block_secpar* keys, size_t counter, block128* output);

// Given VOLE_WIDTH AES keys, generate VOLE_BLOCK block128s of output from each, starting at
// counter.
inline void aes_ctr_vole(const aes_round_keys* aeses, size_t counter, block128* output);

// Given AES_PREFERRED_WIDTH sets of round keys, generate 1 block of output from each in CTR mode,
// starting at counter.
inline void aes_ctr_x1(const aes_round_keys* aeses, size_t counter, block128* output);

// Given AES_PREFERRED_WIDTH/2 sets of round keys, generate 2 block of output from each in CTR mode,
// starting at counter.
inline void aes_ctr_x2(const aes_round_keys* aeses, size_t counter, block128* output);

// Given VOLE_WIDTH Even-Mansour keys, generate VOLE_BLOCK * 128 bits of output from each in CTR
// mode, starting at counter.
inline void aes_ctr_fixed_key_vole(const aes_round_keys* fixed_key, const block128* keys, size_t counter, block128* output);
inline void rijndael256_ctr_fixed_key_vole(const rijndael256_round_keys* fixed_key, const block256* keys, size_t counter, block128* output);

// Given AES_PREFERRED_WIDTH or RIJNDAEL256_PREFERRED_WIDTH Even-Mansour keys, generate 1 block of
// output from each in CTR mode, starting at counter.
inline void aes_ctr_fixed_key_x1(const aes_round_keys* fixed_key, const block128* keys, size_t counter, block128* output);
inline void rijndael256_ctr_fixed_key_x1(const rijndael256_round_keys* fixed_key, const block256* keys, size_t counter, block256* output);

// Given AES_PREFERRED_WIDTH/2 or RIJNDAEL256_PREFERRED_WIDTH/2 Even-Mansour keys, generate 2 block
// of output from each in CTR mode, starting at counter.
inline void aes_ctr_fixed_key_x2(const aes_round_keys* fixed_key, const block128* keys, size_t counter, block128* output);
inline void rijndael256_ctr_fixed_key_x2(const rijndael256_round_keys* fixed_key, const block256* keys, size_t counter, block256* output);

// Same, but for block size = security parameter.
#if SECURITY_PARAM == 128

#define FIXED_KEY_PREFERRED_WIDTH_SHIFT AES_PREFERRED_WIDTH_SHIFT
typedef aes_round_keys rijndael_round_keys;
inline void rijndael_ctr_fixed_key_vole(const rijndael_round_keys* fixed_key, const block_secpar* keys, size_t counter, block_secpar* output)
{
	aes_ctr_fixed_key_vole(fixed_key, keys, counter, output);
}
inline void rijndael_ctr_fixed_key_x1(const rijndael_round_keys* fixed_key, const block_secpar* keys, size_t counter, block_secpar* output)
{
	aes_ctr_fixed_key_x1(fixed_key, keys, counter, output);
}
inline void rijndael_ctr_fixed_key_x2(const rijndael_round_keys* fixed_key, const block_secpar* keys, size_t counter, block_secpar* output)
{
	aes_ctr_fixed_key_x2(fixed_key, keys, counter, output);
}

#elif SECURITY_PARAM == 192

typedef rijndael192_round_keys rijndael_round_keys;

#elif SECURITY_PARAM == 256

#define FIXED_KEY_PREFERRED_WIDTH_SHIFT RIJNDAEL256_PREFERRED_WIDTH_SHIFT
typedef rijndael256_round_keys rijndael_round_keys;
inline void rijndael_ctr_fixed_key_vole(const rijndael_round_keys* fixed_key, const block_secpar* keys, size_t counter, block_secpar* output)
{
	rijndael256_ctr_fixed_key_vole(fixed_key, keys, counter, output);
}
inline void rijndael_ctr_fixed_key_x1(const rijndael_round_keys* fixed_key, const block_secpar* keys, size_t counter, block_secpar* output)
{
	rijndael256_ctr_fixed_key_x1(fixed_key, keys, counter, output);
}
inline void rijndael_ctr_fixed_key_x2(const rijndael_round_keys* fixed_key, const block_secpar* keys, size_t counter, block_secpar* output)
{
	rijndael256_ctr_fixed_key_x2(fixed_key, keys, counter, output);
}

#endif

#endif
