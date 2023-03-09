#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#include <stddef.h>
#include "config.h"

#include "polynomials.h"

// TODO: Should probably use "blocks" much more often than "unsigned char*"s.


// TODO: does this need to change based on even vs odd NIST levels?
// TODO: ditch in favor of sizeof?
#define DIGEST_SIZE (SECURITY_PARAM/4)

// TODO: ought to pick a random oracle that allows parallelization, so that it's compatible if
// anybody wants to make a parallel implementation.
#if defined(RANDOM_ORACLE_SHA3)
# include "sha3.h"

// TODO

typedef TODO random_oracle_state;
typedef TODO random_oracle_digest;

inline void random_oracle_init(random_oracle_state* ro);
// TODO: needed? random_oracle_clone
inline void random_oracle_update(random_oracle_state* ro, const unsigned char* input, size_t size);
inline void random_oracle_final(random_oracle_state* ro, unsigned char* digest);

inline random_oracle_digest random_oracle_digest_xor(random_oracle_digest a, random_oracle_digest b);

// TODO: XOF?
#endif

#include "aes.h"
#include "rijndael.h"

#if defined(PRG_RIJNDAEL_EVEN_MANSOUR)
#include "even_mansour_impl.h"
#elif defined(PRG_AES_CTR)
#include "ctr_impl.h"
#endif

#endif
