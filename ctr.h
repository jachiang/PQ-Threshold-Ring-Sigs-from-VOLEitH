#ifndef CTR_H
#define CTR_H

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

typedef TODO aes128_state;
typedef TODO aes192_state;
typedef TODO aes256_state;
typedef TODO rijndael128x128_state;
typedef TODO rijndael192x192_state;
typedef TODO rijndael256x256_state;

inline void aes_init(aes_state* aes, const unsigned char* key);
inline void aes_enc_block(const aes_state* aes, unsigned char* ctxt, const unsigned char* msg);
inline void aes_enc_pipelined(const aes_state* aes, unsigned char* ctxt, const unsigned char* msg, size_t len);

# elif defined(AES_FIXSLICING)

// TODO

# endif

# if defined(PRG_MANSOUR)
#  include ""

# elif defined(PRG_CTR)

typedef TODO prg_state;

// TODO: probably below definitions should go in aesni.h
inline void prg_init(prg_state* prg, const unsigned char* seed);
inline void prg_gen(prg_state* prg, unsigned char* output, size_t size);
inline void prg_gen_blocks_interleaved(prg_state* prgs, unsigned char* output, size_t num_prgs, size_t num_blocks);

// Expand to 2*PRG_SEED_SIZE bytes
inline void prg_double(prg_state* prg, const unsigned char* seed, unsigned char* output);

// Expand to PRG_SEED_SIZE + DIGEST_SIZE bytes.
inline void prg_digest(prg_state* prg, const unsigned char* seed, unsigned char* output);

# endif

#endif
