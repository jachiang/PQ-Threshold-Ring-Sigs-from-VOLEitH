#ifndef PRIMITIVES_H
#define PRIMITIVES_H

# include <stddef.h>
# include "config.h"

# if defined(GALOIS_FIELD_CLMUL)

#  include "field_clmul.h"

// TODO: probably move below to field_clmul.h
#  include <immintrin.h>
#  include <wmmintrin.h>

// TODO: 3 fields: 128, 196, 256 bits. Each with packed and unpacked versions.  Unpacked versions
// are double length (or at least 64 bits longer, but double seems more useful), to avoid modular reduction.

// TODO: Polys: 64(?), 128, 256, 512(?).

typedef __m128i gf128;
typedef __m256i gf256;

inline gf128 xor_128(gf128 x, gf128 y)
{
	return _mm128_xor_si(x, y);
}

inline gf256 xor_256(gf256 x, gf256 y)
{
	return _mm256_xor_si256(x, y);
}

# elif defined(GALOIS_FIELD_C)

// TODO

# endif

// TODO: Should probably use "blocks" much more often than "unsigned char*"s.


// TODO: does this need to change based on even vs odd NIST levels?
// TODO: ditch in favor of sizeof?
# define DIGEST_SIZE (SECURITY_PARAM/4)

// TODO: ought to pick a random oracle that allows parallelization, so that it's compatible if
// anybody wants to make a parallel implementation.
# if defined(RANDOM_ORACLE_SHA3)
#  include "sha3.h"

// TODO

typedef TODO random_oracle_state;
typedef TODO random_oracle_digest;

inline void random_oracle_init(random_oracle_state* ro);
// TODO: needed? random_oracle_clone
inline void random_oracle_update(random_oracle_state* ro, const unsigned char* input, size_t size);
inline void random_oracle_final(random_oracle_state* ro, unsigned char* digest);

inline random_oracle_digest random_oracle_digest_xor(random_oracle_digest a, random_oracle_digest b);

// TODO: XOF?
# endif

# if defined(AES_NI)
#  include "aesni.h"

// TODO: probably below definitions should go in aesni.h

// AES, with key size == security parameter.
typedef TODO aes_state;

// Rijndael, with block size == key size == security parameter.
typedef TODO rijndael_state;

inline void aes_init(aes_state* cipher, const unsigned char* key);
inline void aes_enc_block(const aes_state* cipher,
                          unsigned char* ctxt, const unsigned char* msg);
inline void aes_enc_pipelined(const aes_state* cipher,
                              unsigned char* ctxt, const unsigned char* msg, size_t len);

inline void rijndael_init(rijndael_state* cipher, const unsigned char* key);
inline void rijndael_enc_block(const rijndael_state* cipher, unsigned char* ctxt,
                               const unsigned char* msg);
inline void rijndael_enc_pipelined(const rijndael_state* cipher,
                                   unsigned char* ctxt, const unsigned char* msg, size_t len);

# elif defined(AES_FIXSLICING)

// TODO

# endif

# if defined(PRG_RIJNDAEL_EVEN_MANSOUR)
#  include "even_mansour_impl.h"
# elif defined(PRG_AES_CTR)
#  include "ctr_impl.h"
# endif

#endif
