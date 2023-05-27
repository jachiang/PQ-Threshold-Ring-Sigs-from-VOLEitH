#ifndef QUICKSILVER_H
#define QUICKSILVER_H

#include "polynomials.h"
#include "universal_hash.h"

#define QUICKSILVER_CHALLENGE_BYTES ((3 * SECURITY_PARAM + 64) / 8)
#define QUICKSILVER_PROOF_BYTES (2 * SECURITY_PARAM / 8)

typedef struct
{
	poly_secpar_vec mac;
	poly1_vec value;
} quicksilver_vec_gf2;

typedef struct
{
	poly_secpar_vec mac;
	poly_secpar_vec value;
} quicksilver_vec_gfsecpar;

typedef struct
{
	bool verifier;
	poly_secpar_vec delta; // All components are equal
	poly_secpar_vec deltaSq; // Ditto

	hasher_gfsecpar_key key_secpar;
	hasher_gfsecpar_state state_secpar_const;
	hasher_gfsecpar_state state_secpar_linear;

	hasher_gfsecpar_64_key key_64;
	hasher_gfsecpar_64_state state_64_const;
	hasher_gfsecpar_64_state state_64_linear;

	poly_secpar_vec hash_combination[2];

	const uint8_t* witness;
	const block_secpar* macs;
} quicksilver_state;

inline void quicksilver_init_hash_keys(quicksilver_state* state, const uint8_t* challenge)
{
	for (size_t i = 0; i < 2; ++i, challenge += SECURITY_PARAM / 8)
		state->hash_combination[i] = poly_secpar_load_dup(challenge);
	poly_secpar_vec hash_key_secpar = poly_secpar_load_dup(challenge);
	poly64_vec hash_key_64 = poly64_load_dup(challenge + SECURITY_PARAM / 8);

	hasher_gfsecpar_init_key(&state->key_secpar, hash_key_secpar);
	hasher_gfsecpar_64_init_key(&state->key_64, hash_key_64);
}

// Initialize a prover's quicksilver_state. challenge must have length QUICKSILVER_CHALLENGE_BYTES.
inline void quicksilver_init_prover(
	quicksilver_state* state, const uint8_t* witness, const block_secpar* macs,
	size_t num_constraints, const uint8_t* challenge)
{
	state->verifier = false;

	quicksilver_init_hash_keys(state, challenge);
	hasher_gfsecpar_init_state(&state->state_secpar_const, num_constraints);
	hasher_gfsecpar_init_state(&state->state_secpar_linear, num_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_const, num_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_linear, num_constraints);

	state->witness = witness;
	state->macs = macs;
}

// Initialize a verifier's quicksilver_state. challenge must have length
// QUICKSILVER_CHALLENGE_BYTES.
inline void quicksilver_init_verifier(
	quicksilver_state* state, const block_secpar* macs, size_t num_constraints,
	block_secpar delta, const uint8_t* challenge)
{
	state->verifier = true;
	state->delta = poly_secpar_load_dup(&delta);
	state->deltaSq = poly_2secpar_reduce_secpar(poly_secpar_mul(state->delta, state->delta));

	quicksilver_init_hash_keys(state, challenge);
	hasher_gfsecpar_init_state(&state->state_secpar_const, num_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_const, num_constraints);

	state->macs = macs;
}

inline quicksilver_vec_gf2 quicksilver_get_witness_vec(const quicksilver_state* state, size_t index)
{
	quicksilver_vec_gf2 out;
	if (!state->verifier)
		out.value = poly1_load(&state->witness[index / 8], index % 8);
	out.mac = poly_secpar_load(&state->macs[index]);
	return out;
}

inline void quicksilver_final(const quicksilver_state* state, bool verifier,
        poly_secpar_vec* hash_const_secpar, poly_secpar_vec* hash_linear_secpar,
        poly_secpar_vec* hash_const_64, poly_secpar_vec* hash_linear_64) {
    *hash_const_64 = hasher_gfsecpar_64_final(&state->state_64_const);
    *hash_const_secpar = hasher_gfsecpar_final(&state->state_secpar_const);
    if (!verifier) {
        *hash_linear_64 = hasher_gfsecpar_64_final(&state->state_64_linear);
        *hash_linear_secpar = hasher_gfsecpar_final(&state->state_secpar_linear);
    }
}

inline poly_secpar_vec quicksilver_get_delta(const quicksilver_state* state) {
    assert(state->verifier);
    return state->delta;
}

inline quicksilver_vec_gf2 quicksilver_add_gf2(const quicksilver_state* state, quicksilver_vec_gf2 x, quicksilver_vec_gf2 y)
{
	quicksilver_vec_gf2 out;
	if (!state->verifier)
		out.value = x.value ^ y.value;
	out.mac = poly_secpar_add(x.mac, y.mac);
	return out;
}

inline quicksilver_vec_gfsecpar quicksilver_add_gfsecpar(const quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y)
{
	quicksilver_vec_gfsecpar out;
	if (!state->verifier)
		out.value = poly_secpar_add(x.value, y.value);
	out.mac = poly_secpar_add(x.mac, y.mac);
	return out;
}

inline quicksilver_vec_gf2 quicksilver_zero_gf2()
{
	quicksilver_vec_gf2 out;
	out.value = 0;
	out.mac = poly_secpar_set_low32(0);
	return out;
}

inline quicksilver_vec_gfsecpar quicksilver_zero_gfsecpar()
{
	quicksilver_vec_gfsecpar out;
	out.value = poly_secpar_set_low32(0);
	out.mac = poly_secpar_set_low32(0);
	return out;
}

inline quicksilver_vec_gf2 quicksilver_one_gf2(const quicksilver_state* state)
{
	quicksilver_vec_gf2 out;
	if (state->verifier)
		out.mac = state->delta;
	else
	{
		out.mac = poly_secpar_set_low32(0);
		out.value = poly1_set_all(0xff);
	}
	return out;
}

inline quicksilver_vec_gfsecpar quicksilver_one_gfsecpar(const quicksilver_state* state)
{
	quicksilver_vec_gfsecpar out;
	if (state->verifier)
		out.mac = state->delta;
	else
	{
		out.mac = poly_secpar_set_low32(0);
		out.value = poly_secpar_set_low32(1);
	}
	return out;
}

inline quicksilver_vec_gf2 quicksilver_const_gf2(const quicksilver_state* state, poly1_vec c)
{
	quicksilver_vec_gf2 out;
	if (state->verifier)
		out.mac = poly1xsecpar_mul(c, state->delta);
	else
	{
		out.mac = poly_secpar_set_low32(0);
		out.value = c;
	}
	return out;
}

inline quicksilver_vec_gfsecpar quicksilver_const_gfsecpar(const quicksilver_state* state, poly_secpar_vec c)
{
	quicksilver_vec_gfsecpar out;
	if (state->verifier)
		out.mac = poly_2secpar_reduce_secpar(poly_secpar_mul(state->delta, c));
	else
	{
		out.mac = poly_secpar_set_low32(0);
		out.value = c;
	}
	return out;
}

inline quicksilver_vec_gf2 quicksilver_mul_const_gf2(const quicksilver_state* state, quicksilver_vec_gf2 x, poly1_vec c)
{
	x.mac = poly1xsecpar_mul(c, x.mac);
	if (!state->verifier)
		x.value &= c;
	return x;
}

inline quicksilver_vec_gfsecpar quicksilver_mul_const(const quicksilver_state* state, quicksilver_vec_gfsecpar x, poly_secpar_vec c)
{
	x.mac = poly_2secpar_reduce_secpar(poly_secpar_mul(c, x.mac));
	if (!state->verifier)
		x.value = poly_2secpar_reduce_secpar(poly_secpar_mul(c, x.value));
	return x;
}

inline quicksilver_vec_gfsecpar quicksilver_combine_8_bits(const quicksilver_state* state, const quicksilver_vec_gf2* qs_bits)
{
	quicksilver_vec_gfsecpar out;

	poly_secpar_vec macs[8];
	for (size_t i = 0; i < 8; ++i)
		macs[i] = qs_bits[i].mac;
	out.mac = poly_secpar_from_8_poly_secpar(macs);

	if (!state->verifier)
	{
		poly1_vec bits[8];
		for (size_t i = 0; i < 8; ++i)
			bits[i] = qs_bits[i].value;
		out.value = poly_secpar_from_8_poly1(bits);
	}

	return out;
}

// Add a constraint of the form x*y == 1.
inline void quicksilver_add_product_constraints(quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y)
{
	if (state->verifier)
	{
		poly_secpar_vec term = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(x.mac, y.mac)), state->deltaSq);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, term);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, term);
	}
	else
	{
		// Use Karatsuba to save a multiplication.
		poly_secpar_vec x0_y0 = poly_2secpar_reduce_secpar(poly_secpar_mul(x.mac, y.mac));
		poly_secpar_vec x1_y1 = poly_2secpar_reduce_secpar(poly_secpar_mul(poly_secpar_add(x.value, x.mac), poly_secpar_add(y.value, y.mac)));
		// Assume that the constraint is valid, so x.value * y.value = 1.
		poly_secpar_vec xinf_yinf = poly_secpar_set_low32(1);
		poly_secpar_vec lin_term = poly_secpar_add(poly_secpar_add(x0_y0, xinf_yinf), x1_y1);

		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, x0_y0);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, lin_term);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, x0_y0);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, lin_term);
	}
}

void quicksilver_prove(const quicksilver_state* state, size_t witness_bits, uint8_t* proof);
bool quicksilver_verify(const quicksilver_state* state, size_t witness_bits, const uint8_t* proof);

#endif
