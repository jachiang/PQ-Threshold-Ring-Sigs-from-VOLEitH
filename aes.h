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

// Number of AES blocks to run in parallel, for maximum performance.
#define AES_PREFERRED_WIDTH (1 << AES_PREFERRED_WIDTH_SHIFT)

// Number of AES blocks encrypted in a single vector register.
#define AES_VECTOR_WIDTH (1 << AES_VECTOR_WIDTH_SHIFT)

// Run AES key schedule on VOLE_WIDTH blocks, then generate VOLE_BLOCK blocks of output from each.
inline void aes_keygen_encrypt_vole(aes_round_keys* aeses, const block128* keys, block128* output);

// Given VOLE_WIDTH AES keys, generate VOLE_BLOCK blocks of output from each.
inline void aes_encrypt_vole(aes_round_keys* aeses, const block128* input, block128* output);

inline void rijndael192_keygen(rijndael192_round_keys* rijndael, block192 key);
inline void rijndael256_keygen(rijndael256_round_keys* rijndael, block256 key);

// Encrypt VOLE_WIDTH * VOLE_BLOCK * 128 bits using the same set of round keys.
inline void aes_encrypt_fixed_key_vole(const aes_round_keys* rijndael, const block128* input, block128* output);
inline void rijndael256_encrypt_fixed_key_vole(const rijndael256_round_keys* rijndael, const block256* input, block256* output);

// Same, but for block size = security parameter.
#if SECURITY_PARAM == 128
typedef aes_round_keys rijndael_round_keys;
inline void rijndael_encrypt_fixed_key_vole(const rijndael_round_keys* rijndael, const block_secpar* input, block_secpar* output)
{
	aes_encrypt_fixed_key_vole(rijndael, input, output);
}
#elif SECURITY_PARAM == 192
typedef rijndael192_round_keys rijndael_round_keys;
#elif SECURITY_PARAM == 256
typedef rijndael256_round_keys rijndael_round_keys;
inline void rijndael_encrypt_fixed_key_vole(const rijndael_round_keys* rijndael, const block_secpar* input, block_secpar* output)
{
	rijndael256_encrypt_fixed_key_vole(rijndael, input, output);
}
#endif

inline void aes_round_function(const aes_round_keys* aes, block128* state, block128* after_sbox, int round);
inline void rijndael192_round_function(const rijndael192_round_keys* aes, block192* state, block192* after_sbox, int round);
inline void rijndael256_round_function(const rijndael256_round_keys* aes, block256* state, block256* after_sbox, int round);

#endif
