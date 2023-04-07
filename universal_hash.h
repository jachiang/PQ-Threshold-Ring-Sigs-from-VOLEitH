#ifndef UNIVERSAL_HASH_H
#define UNIVERSAL_HASH_H

#include <string.h>

#include "polynomials.h"

// Number of powers of the hash key to precompute
#define HASH_SECPAR_KEY_POWS 2
#define HASH_SECPAR_KEY64_POWS 1 // TODO: Is there a good way to do > 1?
#define HASH64_KEY_POWS 2

// TODO: Separate key from state.

typedef struct
{
	poly_secpar_vec key_pows[HASH_SECPAR_KEY_POWS];
} hash_key_secpar;

typedef struct
{
	poly64_vec key_pows[HASH_SECPAR_KEY64_POWS];
} hash_key64_gfsecpar;

typedef struct
{
	poly64_vec key_pows[HASH64_KEY_POWS];
	poly64_vec key_pow_times_a64;
} hash_key64;

typedef poly_secpar_vec hash_secpar_state;
typedef poly_secpar_plus_64_vec hasher_secpar_key64;
typedef poly128_vec hasher64;

// TODO: Probably some of these can go into a .c file, depending on how they get used.

inline void hasher_secpar_init(hasher_secpar* hasher, poly_secpar_vec key)
{
	hasher->key_pows[0] = key;
	poly_secpar_vec key_pow = key;
	for (size_t i = 1; i < HASH_SECPAR_KEY_POWS; ++i)
	{
		key_pow = poly_2secpar_reduce_secpar(poly_secpar_mul(key_pow, key));
		hasher->key_pows[i] = key_pow;
	}

	memset(&hasher->state, 0, sizeof(hasher->state));
}

// Update on HASH_SECPAR_KEY_POWS polynomials.
inline void hasher_secpar_update(hasher_secpar* hasher, const poly_secpar_vec* input)
{
	poly_2secpar_vec state =
		poly_secpar_mul(hasher->state, hasher->key_pows[HASH_SECPAR_KEY_POWS - 1]);

	poly_secpar_vec summands[HASH_SECPAR_KEY_POWS + 1];
	for (size_t i = 0; i < HASH_SECPAR_KEY_POWS; ++i)
	{
		poly_secpar_vec x = input[i];
		if (i > 0)
			summands[i] = poly_secpar_mul(secpar, hasher->key_pows[i - 1]);
		else
			summands[i] = poly_secpar_add(poly_2secpar_from_secpar(x), state);
	}
	summands[HASH_SECPAR_KEY_POWS] = state;

	for (size_t d = 0; (1 << d) < HASH_SECPAR_KEY_POWS + 1; ++d)
		for (size_t i = 0; (i + (1 << d)) < HASH_SECPAR_KEY_POWS + 1; i += (2 << d))
			input_muls[i] = poly_2secpar_add(input_muls[i], input_muls[i + (1 << d)]);

	hasher->state = poly_2secpar_reduce_secpar(input_muls[0]);
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
