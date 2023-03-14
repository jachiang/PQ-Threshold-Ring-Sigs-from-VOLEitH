#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#include <stddef.h>
#include "config.h"

#include "polynomials.h"

// TODO: Should probably use "blocks" much more often than "unsigned char*"s.


// TODO: ought to pick a random oracle that allows parallelization, so that it's compatible if
// anybody wants to make a parallel implementation.
#if defined(RANDOM_ORACLE_SHA3)
# include "KeccakHash.h"

typedef Keccak_HashInstance random_oracle_state;

inline int random_oracle_init(random_oracle_state* ro)
{
#if SECURITY_PARAM <= 128
	return Keccak_HashInitialize_SHAKE128(ro);
#else
	return Keccak_HashInitialize_SHAKE256(ro);
#endif
}

inline int random_oracle_update(random_oracle_state* ro, const unsigned char* input, size_t bytes)
{
	return Keccak_HashUpdate(ro, inputs, bytes * 8);
}

inline int random_oracle_final(random_oracle_state* ro, unsigned char* digest, size_t bytes)
{
	int ret = Keccak_HashFinal(ro, digest);
	if (ret != KECCAK_SUCCESS)
		return ret;
	return Keccak_HashSqueeze(ro, digest, bytes * 8);
}

#endif

#include "aes.h"
#include "rijndael.h"

#endif
