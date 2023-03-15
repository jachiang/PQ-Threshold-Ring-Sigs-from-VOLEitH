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

// Run aes key schedule on n different keys. Maybe not needed?
inline void aes_keygen1(aes_round_keys* aes, const block128* key);
inline void aes_keygen2(aes_round_keys* aes, const block128* key);
inline void aes_keygen4(aes_round_keys* aes, const block128* key);
inline void aes_keygen8(aes_round_keys* aes, const block128* key);
inline void aes_keygen16(aes_round_keys* aes, const block128* key);

// Run AES key schedule on AES_PREFERRED_WIDTH blocks (TODO: Maybe something different?), then
// generate 2*secpar blocks of output from each.
inline void aes_keygen_preferred_encrypt_2_secpar(aes_round_keys* aes, const block128* key);

// Run AES key schedule on AES_PREFERRED_WIDTH blocks (TODO: Maybe something different?), then
// generate BLOCK_PREFERRED_LEN_SHIFT blocks of output from each.
inline void aes_keygen_preferred_encrypt_preferred(aes_round_keys* aes, const block128* key);

// Encrypt n blocks with n keys. Maybe not needed?
inline void aes_encrypt1(const aes_round_keys* aes, const block128* input, block128* output);
inline void aes_encrypt2(const aes_round_keys* aes, const block128* input, block128* output);
inline void aes_encrypt4(const aes_round_keys* aes, const block128* input, block128* output);
inline void aes_encrypt8(const aes_round_keys* aes, const block128* input, block128* output);
inline void aes_encrypt16(const aes_round_keys* aes, const block128* input, block128* output);

// Same as aes_encrypt<AES_PREFERRED_WIDTH>.
inline void aes_encrypt_preferred(const aes_round_keys* aes, const block128* input, block128* output);

inline void aes_round_function(const aes_round_keys* aes, block128* state, block128* after_sbox, int round);

#endif
