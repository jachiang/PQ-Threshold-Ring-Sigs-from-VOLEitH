#ifndef UNIVERSAL_HASH_H
#define UNIVERSAL_HASH_H

#include <assert.h>
#include <string.h>

#include "polynomials.h"

// Number of powers of the hash key to precompute
#define HASH_SECPAR_KEY_POWS 2
#define HASH_SECPAR_KEY64_POWS 1 // TODO: Is there a good way to do > 1?
#define HASH64_KEY_POWS 2

typedef struct
{
	poly_secpar_vec key_pows[HASH_SECPAR_KEY_POWS];
} hasher_gfsecpar_key;

typedef struct
{
	poly64_vec key_pows[HASH_SECPAR_KEY64_POWS];
} hasher_gfsecpar_64_key;

typedef struct
{
	poly64_vec key_pows[HASH64_KEY_POWS];
	poly64_vec key_pow_times_a64;
} hasher_gf64_key;

typedef struct
{
	poly_2secpar_vec state;
	int pow;
} hasher_gfsecpar_state;

typedef poly_secpar_plus_64_vec hasher_gfsecpar_64_state;
typedef poly128_vec hasher_gf64_state;

inline void hasher_gfsecpar_init_key(hasher_gfsecpar_key* hash_key, poly_secpar_vec key)
{
	hash_key->key_pows[0] = key;
	poly_secpar_vec key_pow = key;
	for (size_t i = 1; i < HASH_SECPAR_KEY_POWS; ++i)
	{
		key_pow = poly_2secpar_reduce_secpar(poly_secpar_mul(key_pow, key));
		hash_key->key_pows[i] = key_pow;
	}
}

inline void hasher_gfsecpar_init_state(hasher_gfsecpar_state* state)
{
	memset(&state, 0, sizeof(*state));
	state->pow = HASH_SECPAR_KEY_POWS - 1;
}

// Update a vector of hashers on a vector of polynomials.
inline void hasher_secpar_update(const hasher_gfsecpar_key* key, hasher_gfsecpar_state* state, poly_secpar_vec input)
{
	if (state->pow == -1)
	{
		state->state = poly_secpar_mul(key->key_pow[HASH_SECPAR_KEY_POWS - 1], poly_2secpar_reduce_secpar(state->state));
		state->pow = HASH_SECPAR_KEY_POWS - 1;
	}

	poly_2secpar_vec summand;
	if (state->pow > 0)
		summand = poly_secpar_mul(key->key_pows[state->pow - 1], input);
	else
		summand = poly_2secpar_from_secpar(input);
	state->state = poly_2secpar_add(state->state, summand);
	--state->pow;
}

inline poly_secpar_vec hasher_secpar_final(const hasher_gfsecpar_state* state)
{
	assert(state->pow == -1);
	return poly_2secpar_reduce_secpar(state->state);
}

inline void hasher64_init(hasher64* hasher, poly64_vec key)
{
	hasher->key_pows[0] = key;
	poly64_vec key_pow = key;
	for (size_t i = 1; i < HASH64_KEY_POWS; ++i)
	{
		key_pow = poly128_reduce64(poly64_mul(key_pow, key));
		hasher->key_pows[i] = key_pow;
	}

	memset(&hasher->state, 0, sizeof(hasher->state));
}

#endif
