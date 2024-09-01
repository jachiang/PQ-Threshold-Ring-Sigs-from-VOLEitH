#ifndef QUICKSILVER_H
#define QUICKSILVER_H

#include "config.h"
#include "polynomials.h"
#include "universal_hash.h"
#include "util.h"
#include <stdio.h> // JC: for debugging.

#define QUICKSILVER_CHALLENGE_BYTES ((3 * SECURITY_PARAM + 64) / 8)
#define QUICKSILVER_PROOF_BYTES (SECURITY_PARAM / 8)
#define QUICKSILVER_CHECK_BYTES (SECURITY_PARAM / 8)

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
	poly_secpar_vec c0;
	poly_secpar_vec c1;
} qs_prover_poly_deg1;

typedef struct
{
	poly_secpar_vec c0;
	poly_secpar_vec c1;
	poly_secpar_vec c2;
} qs_prover_poly_deg2;

typedef struct
{
	poly_secpar_vec c0;
	poly_secpar_vec c1;
	poly_secpar_vec c2;
	poly_secpar_vec c3;
} qs_prover_poly_deg3;

typedef struct
{
	poly_secpar_vec c0;
	poly_secpar_vec c1;
	poly_secpar_vec c2;
	poly_secpar_vec c3;
	poly_secpar_vec c4;
} qs_prover_poly_deg4;

typedef struct
{
	poly_secpar_vec c0;
	poly_secpar_vec c1;
	poly_secpar_vec c2;
	poly_secpar_vec c3;
	poly_secpar_vec c4;
	poly_secpar_vec c5;
	poly_secpar_vec c6;
} qs_prover_poly_deg6;

typedef struct
{
	poly_secpar_vec key;
	size_t deg;
} qs_verifier_key;

typedef struct
{
	bool verifier;
	poly_secpar_vec delta; // All components are equal
	poly_secpar_vec deltaSq; // Ditto

	hasher_gfsecpar_key key_secpar;
	// JC: Satisfied KE/OWF constraints.
	hasher_gfsecpar_state state_secpar_const;
	hasher_gfsecpar_state state_secpar_linear;
	hasher_gfsecpar_state state_secpar_quad;
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hasher_gfsecpar_state state_secpar_cubic;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hasher_gfsecpar_state state_secpar_quartic;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hasher_gfsecpar_state state_secpar_quintic;
	#endif

	// JC: (Dis)satisfied OWF constraints.
	hasher_gfsecpar_state state_or_secpar_const[FAEST_RING_SIZE];
	hasher_gfsecpar_state state_or_secpar_linear[FAEST_RING_SIZE];
	hasher_gfsecpar_state state_or_secpar_quad[FAEST_RING_SIZE];

	hasher_gfsecpar_64_key key_64;
	// JC: Satisfied KE/OWF constraints.
	hasher_gfsecpar_64_state state_64_const;
	hasher_gfsecpar_64_state state_64_linear;
	hasher_gfsecpar_64_state state_64_quad;
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hasher_gfsecpar_64_state state_64_cubic;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hasher_gfsecpar_64_state state_64_quartic;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hasher_gfsecpar_64_state state_64_quintic;
	#endif

	// JC: (Dis)satisfied OWF constraints.
	hasher_gfsecpar_64_state state_or_64_const[FAEST_RING_SIZE];
	hasher_gfsecpar_64_state state_or_64_linear[FAEST_RING_SIZE];
	hasher_gfsecpar_64_state state_or_64_quad[FAEST_RING_SIZE];

	poly_secpar_vec hash_combination[2];

	const uint8_t* witness;
	const block_secpar* macs;
} quicksilver_state;

// Initialize a prover's quicksilver_state. challenge must have length QUICKSILVER_CHALLENGE_BYTES.
void quicksilver_init_prover(
	quicksilver_state* state, const uint8_t* witness, const block_secpar* macs,
	size_t num_constraints, const uint8_t* challenge);

void quicksilver_init_or_prover(
	quicksilver_state* state, const uint8_t* witness, const block_secpar* macs,
	size_t num_owf_constraints, size_t num_ke_constraints, const uint8_t* challenge);

// Initialize a verifier's quicksilver_state. challenge must have length
// QUICKSILVER_CHALLENGE_BYTES.
void quicksilver_init_verifier(
	quicksilver_state* state, const block_secpar* macs, size_t num_constraints,
	block_secpar delta, const uint8_t* challenge);

void quicksilver_init_or_verifier(
	quicksilver_state* state, const block_secpar* macs, size_t num_owf_constraints, size_t num_ke_constraints,
	block_secpar delta, const uint8_t* challenge);

inline quicksilver_vec_gf2 quicksilver_get_witness_vec(const quicksilver_state* state, size_t index)
{
	quicksilver_vec_gf2 out;
	if (!state->verifier)
	{
		uint16_t tmp;

		// This won't overflow the bounds of witness because the are extra masking bits at the end,
		// which won't get accessed through this function.
		memcpy(&tmp, &state->witness[index / 8], sizeof(tmp));
		out.value = poly1_load(tmp, index % 8);
	}
	out.mac = poly_secpar_load(&state->macs[index]);
	return out;
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
	out.mac = poly_secpar_set_zero();
	return out;
}

inline quicksilver_vec_gfsecpar quicksilver_zero_gfsecpar()
{
	quicksilver_vec_gfsecpar out;
	out.value = poly_secpar_set_zero();
	out.mac = poly_secpar_set_zero();
	return out;
}

inline quicksilver_vec_gf2 quicksilver_one_gf2(const quicksilver_state* state)
{
	quicksilver_vec_gf2 out;
	if (state->verifier)
		out.mac = state->delta;
	else
	{
		out.mac = poly_secpar_set_zero();
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
		out.mac = poly_secpar_set_zero();
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
		out.mac = poly_secpar_set_zero();
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
		out.mac = poly_secpar_set_zero();
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

// load 8 consecutive bits from s into QS GF(2) values, then combine them into a GF(2^secpar) value
// in the GF(2^8) subfield
inline quicksilver_vec_gfsecpar quicksilver_const_8_bits(const quicksilver_state* state, const void* s)
{
    quicksilver_vec_gf2 input_bits[8];
    for (size_t bit_j = 0; bit_j < 8; ++bit_j) {
        input_bits[bit_j] = quicksilver_const_gf2(state, poly1_load(*(uint8_t*)s, bit_j));
    }
    return quicksilver_combine_8_bits(state, input_bits);
}

// load 8 consecutive bits from the witness and combine them into a GF(2^secpar) value in the
// GF(2^8) subfield
inline quicksilver_vec_gfsecpar quicksilver_get_witness_8_bits(const quicksilver_state* state, size_t bit_index)
{
    quicksilver_vec_gf2 input_bits[8];
    for (size_t bit_j = 0; bit_j < 8; ++bit_j) {
        input_bits[bit_j] = quicksilver_get_witness_vec(state, bit_index + bit_j);
    }
    return quicksilver_combine_8_bits(state, input_bits);
}

// Add a constraint of the form x*y == 1.
inline void quicksilver_add_product_constraints(quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y, bool ring)
{
	if (state->verifier)
	{
		poly_secpar_vec term = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(x.mac, y.mac)), state->deltaSq);
		if (ring){
			term = poly_2secpar_reduce_secpar(poly_secpar_mul(term, state->delta));
			#if (FAEST_RING_HOTVECTOR_DIM > 1)
			term = poly_2secpar_reduce_secpar(poly_secpar_mul(term, state->delta));
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 2)
			term = poly_2secpar_reduce_secpar(poly_secpar_mul(term, state->delta));
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 3)
			term = poly_2secpar_reduce_secpar(poly_secpar_mul(term, state->delta));
			#endif
		}
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
		assert(poly_secpar_eq(poly_2secpar_reduce_secpar(poly_secpar_mul(x.value, y.value)), xinf_yinf));

		poly_secpar_vec lin_term = poly_secpar_add(poly_secpar_add(x0_y0, xinf_yinf), x1_y1);
		if (ring) {
			#if (FAEST_RING_HOTVECTOR_DIM == 1)
			// JC: For hotvector dim 1, the final satisified QS poly degree is 3.
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_set_zero());
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, x0_y0);
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, lin_term);
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_set_zero());
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, x0_y0);
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, lin_term);
			#elif (FAEST_RING_HOTVECTOR_DIM == 2)
			// JC: For hotvector dim 2, the final satisified QS poly degree is 4.
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_set_zero());
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_set_zero());
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, x0_y0);
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, lin_term);
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_set_zero());
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_set_zero());
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, x0_y0);
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, lin_term);
			#elif (FAEST_RING_HOTVECTOR_DIM == 4)
			// JC: For hotvector dim 4, the final satisified QS poly degree is 6.
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_set_zero());
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_set_zero());
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, poly_secpar_set_zero());
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, poly_secpar_set_zero());
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quartic, x0_y0);
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quintic, lin_term);
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_set_zero());
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_set_zero());
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, poly_secpar_set_zero());
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, poly_secpar_set_zero());
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quartic, x0_y0);
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quintic, lin_term);
			#endif
		}
		else{
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, x0_y0);
			hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, lin_term);
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, x0_y0);
			hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, lin_term);
		}
	}
}

// Add a constraint of the form x*y == 1.
inline void quicksilver_add_product_constraints_to_branch(quicksilver_state* state, size_t branch, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y)
{
	if (state->verifier)
	{
		// JC: Adopted for verifier. Verifier only caches constraint terms to const state member.
		poly_secpar_vec term = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(x.mac, y.mac)), state->deltaSq);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_or_secpar_const[branch], term);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_or_64_const[branch], term);
	}
	else
	{
		// Use Karatsuba to save a multiplication.
		poly_secpar_vec x0_y0 = poly_2secpar_reduce_secpar(poly_secpar_mul(x.mac, y.mac));
		poly_secpar_vec x1_y1 = poly_2secpar_reduce_secpar(poly_secpar_mul(poly_secpar_add(x.value, x.mac), poly_secpar_add(y.value, y.mac)));

		// poly_secpar_vec xinf_yinf = poly_secpar_set_low32(1);
		poly_secpar_vec xinf_yinf = poly_2secpar_reduce_secpar(poly_secpar_mul(x.value, y.value));

		// JC removed: Assert this for active branch?
		// assert(poly_secpar_eq(poly_2secpar_reduce_secpar(poly_secpar_mul(x.value, y.value)), xinf_yinf));

		// JC: x1_y1 is not lin term because it includes x.value*y.value and x.mac*y.mac subterms,
		// JC: These are removed here.
		poly_secpar_vec lin_term = poly_secpar_add(poly_secpar_add(x0_y0, xinf_yinf), x1_y1);

		// JC added: quad_term
		poly_secpar_vec quad_term = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(x.value, y.value)),
													poly_secpar_set_low32(1));
		// JC: Store constraint terms (quad, lin, const) to quicksilver (hasher) state.
		hasher_gfsecpar_update(&state->key_secpar, &state->state_or_secpar_const[branch], x0_y0);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_or_secpar_linear[branch], lin_term);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_or_secpar_quad[branch], quad_term);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_or_64_const[branch], x0_y0);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_or_64_linear[branch], lin_term);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_or_64_quad[branch], quad_term);
	}
}

inline void quicksilver_prover_init_poly_deg1(const quicksilver_state* state, qs_prover_poly_deg1* in)
{
	assert(!state->verifier);
	in->c0 = poly_secpar_set_zero();
	in->c1 = poly_secpar_set_zero();
}

inline void quicksilver_prover_init_poly_deg2(const quicksilver_state* state, qs_prover_poly_deg2* in)
{
	assert(!state->verifier);
	in->c0 = poly_secpar_set_zero();
	in->c1 = poly_secpar_set_zero();
	in->c2 = poly_secpar_set_zero();
}

inline void quicksilver_verifier_init_key_0(const quicksilver_state* state, qs_verifier_key* in)
{
	assert(state->verifier);
	in->key = poly_secpar_set_zero();
	in->deg = 1;
}

inline qs_prover_poly_deg1 qs_prover_poly_deg1_add_deg1(const quicksilver_state* state, const qs_prover_poly_deg1 left, const qs_prover_poly_deg1 right)
{
	assert(!state->verifier);
	qs_prover_poly_deg1 out;
	out.c0 = poly_secpar_add(left.c0,right.c0);
	out.c1 = poly_secpar_add(left.c1,right.c1);
	return out;
}

inline qs_prover_poly_deg1 qs_prover_poly_const_add_deg1(const quicksilver_state* state, const poly_secpar_vec left, const qs_prover_poly_deg1 right)
{
	assert(!state->verifier);
	qs_prover_poly_deg1 out;
	out.c0 = right.c0;
	out.c1 = poly_secpar_add(left,right.c1);
	return out;
}

inline qs_prover_poly_deg2 qs_prover_poly_deg2_add_deg2(const quicksilver_state* state, const qs_prover_poly_deg2 left, const qs_prover_poly_deg2 right)
{
	assert(!state->verifier);
	qs_prover_poly_deg2 out;
	out.c0 = poly_secpar_add(left.c0,right.c0);
	out.c1 = poly_secpar_add(left.c1,right.c1);
	out.c2 = poly_secpar_add(left.c2,right.c2);
	return out;
}

inline qs_prover_poly_deg1 qs_prover_poly_const_mul_deg1(const quicksilver_state* state, const poly_secpar_vec left, const qs_prover_poly_deg1 right)
{
	assert(!state->verifier);
	qs_prover_poly_deg1 out;
	out.c0 = poly_2secpar_reduce_secpar(poly_secpar_mul(left,right.c0));
	out.c1 = poly_2secpar_reduce_secpar(poly_secpar_mul(left,right.c1));
	return out;
}

inline qs_prover_poly_deg2 qs_prover_poly_deg1_mul_deg1(const quicksilver_state* state, const qs_prover_poly_deg1 left, const qs_prover_poly_deg1 right)
{
	assert(!state->verifier);
	poly_secpar_vec out_vec[3] = {poly_secpar_set_zero()};
	poly_secpar_vec left_vec[2] = {left.c0, left.c1};
	poly_secpar_vec right_vec[2] = {right.c0, right.c1};
	qs_polynomial_mul(left_vec, 2, right_vec, 2, out_vec);
	qs_prover_poly_deg2 out_d2;
	out_d2.c0 = out_vec[0];
	out_d2.c1 = out_vec[1];
	out_d2.c2 = out_vec[2];
	return out_d2;
}

inline qs_prover_poly_deg3 qs_prover_poly_deg1_mul_deg2(const quicksilver_state* state, const qs_prover_poly_deg1 left, const qs_prover_poly_deg2 right)
{
	assert(!state->verifier);
	poly_secpar_vec out_vec[4] = {poly_secpar_set_zero()};
	poly_secpar_vec left_vec[2] = {left.c0, left.c1};
	poly_secpar_vec right_vec[3] = {right.c0, right.c1, right.c2};
	qs_polynomial_mul(left_vec, 2, right_vec, 3, out_vec);
	qs_prover_poly_deg3 out_d3;
	out_d3.c0 = out_vec[0];
	out_d3.c1 = out_vec[1];
	out_d3.c2 = out_vec[2];
	out_d3.c3 = out_vec[3];
	return out_d3;
}

inline qs_prover_poly_deg4 qs_prover_poly_deg2_mul_deg2(const quicksilver_state* state, const qs_prover_poly_deg2 left, const qs_prover_poly_deg2 right)
{
	assert(!state->verifier);
	poly_secpar_vec out_vec[5] = {poly_secpar_set_zero()};
	poly_secpar_vec left_vec[3] = {left.c0, left.c1, left.c2};
	poly_secpar_vec right_vec[3] = {right.c0, right.c1, right.c2};
	qs_polynomial_mul(left_vec, 3, right_vec, 3, out_vec);
	qs_prover_poly_deg4 out_d4;
	out_d4.c0 = out_vec[0];
	out_d4.c1 = out_vec[1];
	out_d4.c2 = out_vec[2];
	out_d4.c3 = out_vec[3];
	out_d4.c4 = out_vec[4];
	return out_d4;
}

inline qs_prover_poly_deg6 qs_prover_poly_deg2_mul_deg4(const quicksilver_state* state, const qs_prover_poly_deg2 left, const qs_prover_poly_deg4 right)
{
	assert(!state->verifier);
	poly_secpar_vec out_vec[7] = {poly_secpar_set_zero()};
	poly_secpar_vec left_vec[3] = {left.c0, left.c1, left.c2};
	poly_secpar_vec right_vec[5] = {right.c0, right.c1, right.c2, right.c3, right.c4};
	qs_polynomial_mul(left_vec, 3, right_vec, 5, out_vec);
	qs_prover_poly_deg6 out_d6;
	out_d6.c0 = out_vec[0];
	out_d6.c1 = out_vec[1];
	out_d6.c2 = out_vec[2];
	out_d6.c3 = out_vec[3];
	out_d6.c4 = out_vec[4];
	out_d6.c5 = out_vec[5];
	out_d6.c6 = out_vec[6];
	return out_d6;
}

inline qs_verifier_key quicksilver_verifier_const_add_key(const quicksilver_state* state, const poly_secpar_vec left, const qs_verifier_key right)
{
	assert(state->verifier);
	poly_secpar_vec tmp = state->delta;
	for (size_t i = 0; i < right.deg-1; ++i)
	{
		tmp = poly_2secpar_reduce_secpar(poly_secpar_mul(tmp,state->delta));
	}
	tmp = poly_2secpar_reduce_secpar(poly_secpar_mul(left, tmp));
	qs_verifier_key res;
	res.key = poly_secpar_add(tmp, right.key);
	res.deg = right.deg;
	return res;
}

inline qs_verifier_key quicksilver_verifier_const_mul_key(const quicksilver_state* state, const poly_secpar_vec left, const qs_verifier_key right)
{
	assert(state->verifier);
	qs_verifier_key res;
	res.key = poly_2secpar_reduce_secpar(poly_secpar_mul(left, right.key));
	res.deg = right.deg;
	return res;
}

inline qs_verifier_key quicksilver_verifier_key_add_key(const quicksilver_state* state, const qs_verifier_key left, const qs_verifier_key right)
{
	assert(state->verifier);
	size_t max_deg;
	qs_verifier_key left_tmp = left;
	qs_verifier_key right_tmp = right;
	if (left.deg > right.deg) {
        max_deg = left.deg;
		for (size_t i = 0; i < left.deg - right.deg; ++i)
		{
			right_tmp.key = poly_2secpar_reduce_secpar(poly_secpar_mul(right_tmp.key, state->delta));
		}
		right_tmp.deg = max_deg;
    }
	else if (right.deg > left.deg) {
		max_deg = right.deg;
		for (size_t i = 0; i < right.deg - left.deg; ++i)
		{
			left_tmp.key = poly_2secpar_reduce_secpar(poly_secpar_mul(left_tmp.key, state->delta));
		}
		left_tmp.deg = max_deg;
	}
	else {
		max_deg = left.deg;
	}
	qs_verifier_key res;
	res.deg = max_deg;
	res.key = poly_secpar_add(left.key, right.key);
	return res;
}

inline qs_verifier_key quicksilver_verifier_key_mul_key(const quicksilver_state* state, const qs_verifier_key left, const qs_verifier_key right)
{
	assert(state->verifier);
	qs_verifier_key res;
	res.deg = left.deg + right.deg;
	res.key = poly_2secpar_reduce_secpar(poly_secpar_mul(left.key, right.key));
	return res;
}

inline void quicksilver_verifier_increase_key_deg(const quicksilver_state* state, qs_verifier_key* in, size_t deg)
{
	assert(state->verifier);
	for (size_t i = 0; i < deg; ++i)
	{
		in->key = poly_2secpar_reduce_secpar(poly_secpar_mul(in->key, state->delta));
		in->deg = in->deg + 1;
	}
}

void quicksilver_prove(const quicksilver_state* restrict state, size_t witness_bits,
                       uint8_t* restrict proof, uint8_t* restrict check);
void quicksilver_verify(const quicksilver_state* restrict state, size_t witness_bits,
                        const uint8_t* restrict proof, uint8_t* restrict check);

#if (FAEST_RING_HOTVECTOR_DIM == 1)
void quicksilver_prove_or(quicksilver_state* state, size_t witness_bits,
                          uint8_t* restrict proof_quad, uint8_t* restrict proof_lin, uint8_t* restrict check);
void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin, uint8_t* restrict check);
#elif (FAEST_RING_HOTVECTOR_DIM == 2)
void quicksilver_prove_or(quicksilver_state* state, size_t witness_bits, uint8_t* restrict proof_cubic,
                          uint8_t* restrict proof_quad, uint8_t* restrict proof_lin, uint8_t* restrict check);
void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits, const uint8_t* restrict proof_cubic,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin, uint8_t* restrict check);
#elif (FAEST_RING_HOTVECTOR_DIM == 4)
void quicksilver_prove_or(quicksilver_state* state, size_t witness_bits, uint8_t* restrict proof_quintic,
						  uint8_t* restrict proof_quartic, uint8_t* restrict proof_cubic,
                          uint8_t* restrict proof_quad, uint8_t* restrict proof_lin,
						  uint8_t* restrict check);
void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits, const uint8_t* restrict proof_quintic,
						   const uint8_t* restrict proof_quartic, const uint8_t* restrict proof_cubic,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin,
						   uint8_t* restrict check);
#endif

#endif
