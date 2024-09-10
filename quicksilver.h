#ifndef QUICKSILVER_H
#define QUICKSILVER_H

#include "polynomials.h"
#include "universal_hash.h"
#include "util.h"

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

// Represents a degree two polynomial of delta, which come from multiplications between
// quicksilver_vec_gfsecpar values. For the prover: mac0 is the evaluation at 0, and mac1 is the
// evaluation at 1. The verifier instead only knows the evaluation at delta, which is stored in
// mac0.
//
// Note that to completely represent the polynomial, the prover ought to also store `value`, the
// evaluation at infinity (i.e., the plaintext value). However, if the prover assumes that the
// witness always satisfies the relation, we can skip keeping track of it, as the constraint will
// say what it is supposed to be in the end.
//
// The values are stored unreduced (with poly_2secpar_vec), to delay reductions as much as possible.
// This helps if there tends to be additions combining multiple products together, before they need
// to be reduced.
typedef struct
{
	poly_2secpar_vec mac0;
	poly_2secpar_vec mac1;
	// poly_2secpar_vec value;
} quicksilver_vec_deg2;

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

// Initialize a prover's quicksilver_state. challenge must have length QUICKSILVER_CHALLENGE_BYTES.
void quicksilver_init_prover(
	quicksilver_state* state, const uint8_t* witness, const block_secpar* macs,
	size_t num_constraints, const uint8_t* challenge);

// Initialize a verifier's quicksilver_state. challenge must have length
// QUICKSILVER_CHALLENGE_BYTES.
void quicksilver_init_verifier(
	quicksilver_state* state, const block_secpar* macs, size_t num_constraints,
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

inline quicksilver_vec_deg2 quicksilver_add_deg2(const quicksilver_state* state, quicksilver_vec_deg2 x, quicksilver_vec_deg2 y)
{
	quicksilver_vec_deg2 out;
	out.mac0 = poly_2secpar_add(x.mac0, y.mac0);
	if (!state->verifier)
	{
		out.mac1 = poly_2secpar_add(x.mac1, y.mac1);
		// out.value = poly_2secpar_add(x.value, y.value);
	}
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

inline quicksilver_vec_deg2 quicksilver_zero_deg2()
{
	quicksilver_vec_deg2 out;
	out.mac0 = poly_2secpar_set_zero();
	out.mac1 = poly_2secpar_set_zero();
	// out.value = poly_2secpar_set_zero();
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

inline quicksilver_vec_deg2 quicksilver_one_deg2(const quicksilver_state* state)
{
	quicksilver_vec_deg2 out;
	if (state->verifier)
		out.mac0 = poly_2secpar_from_secpar(state->deltaSq);
	else
	{
		out.mac0 = poly_2secpar_set_zero();
		out.mac1 = poly_2secpar_from_secpar(poly_secpar_set_low32(1));
		// out.value = poly_2secpar_from_secpar(poly_secpar_set_low32(1));
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

inline quicksilver_vec_deg2 quicksilver_const_deg2(const quicksilver_state* state, poly_secpar_vec c)
{
	quicksilver_vec_deg2 out;
	if (state->verifier)
		out.mac0 = poly_secpar_mul(state->deltaSq, c);
	else
	{
		out.mac0 = poly_2secpar_set_zero();
		out.mac1 = poly_2secpar_from_secpar(c);
		// out.value = poly_2secpar_from_secpar(c);
	}
	return out;
}

inline quicksilver_vec_deg2 quicksilver_const_deg2_gf2(const quicksilver_state* state, poly1_vec c)
{
	quicksilver_vec_deg2 out;
	if (state->verifier)
		out.mac0 = poly_2secpar_from_secpar(poly1xsecpar_mul(c, state->deltaSq));
	else
	{
		out.mac0 = poly_2secpar_set_zero();
		out.mac1 = poly_2secpar_from_secpar(poly_secpar_from_1(c));
		// out.value = poly_2secpar_from_secpar(poly_secpar_from_1(c));
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

inline quicksilver_vec_gfsecpar quicksilver_mul_const_gf2_gfsecpar(const quicksilver_state* state, quicksilver_vec_gf2 x, poly_secpar_vec c)
{
	quicksilver_vec_gfsecpar out;
	out.mac = poly_2secpar_reduce_secpar(poly_secpar_mul(c, x.mac));
	if (!state->verifier)
		out.value = poly1xsecpar_mul(x.value, c);
	return out;
}

inline quicksilver_vec_gfsecpar quicksilver_mul_const(const quicksilver_state* state, quicksilver_vec_gfsecpar x, poly_secpar_vec c)
{
	x.mac = poly_2secpar_reduce_secpar(poly_secpar_mul(c, x.mac));
	if (!state->verifier)
		x.value = poly_2secpar_reduce_secpar(poly_secpar_mul(c, x.value));
	return x;
}

inline quicksilver_vec_deg2 quicksilver_mul_const_deg2_gf2(const quicksilver_state* state, quicksilver_vec_deg2 x, poly1_vec c)
{
	quicksilver_vec_deg2 out;
	out.mac0 = poly1x2secpar_mul(c, x.mac0);
	if (!state->verifier)
	{
		out.mac1 = poly1x2secpar_mul(c, x.mac1);
		// out.value = poly1x2secpar_mul(c, x.value);
	}
	return out;
}

inline quicksilver_vec_deg2 quicksilver_mul_const_deg2(const quicksilver_state* state, quicksilver_vec_deg2 x, poly_secpar_vec c)
{
	quicksilver_vec_deg2 out;
	out.mac0 = poly_secpar_mul(c, poly_2secpar_reduce_secpar(x.mac0));
	if (!state->verifier)
	{
		out.mac1 = poly_secpar_mul(c, poly_2secpar_reduce_secpar(x.mac1));
		// out.value = poly_secpar_mul(c, poly_2secpar_reduce_secpar(x.value));
	}
	return out;
}

inline quicksilver_vec_deg2 quicksilver_mul(const quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y)
{
	quicksilver_vec_deg2 out;
	out.mac0 = poly_secpar_mul(x.mac, y.mac);
	if (!state->verifier)
	{
		out.mac1 = poly_secpar_mul(poly_secpar_add(x.value, x.mac), poly_secpar_add(y.value, y.mac));
		// out.value = poly_secpar_mul(x.value, y.value);
	}
	return out;
}

inline quicksilver_vec_gfsecpar quicksilver_combine_1_bit(const quicksilver_state* state, const quicksilver_vec_gf2 qs_bit)
{
	quicksilver_vec_gfsecpar out;
	out.mac = qs_bit.mac;
	if (!state->verifier)
		out.value = poly_secpar_from_1(qs_bit.value);
	return out;
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

// NEW
inline quicksilver_vec_gfsecpar quicksilver_combine_secpar_bits(const quicksilver_state* state, const quicksilver_vec_gf2* qs_bits) {
	quicksilver_vec_gfsecpar out;
	#if SECURITY_PARAM == 128
	poly_secpar_vec macs[128];
	for (size_t i = 0; i < 128; ++i) {
		macs[i] = qs_bits[i].mac;
	}
	out.mac = poly_secpar_from_secpar_poly_secpar(macs);
	if (!state->verifier)
	{
		poly1_vec bits[128];
		for (size_t i = 0; i < 128; ++i) {
			bits[i] = qs_bits[i].value;
		}
		out.value = poly_secpar_from_secpar_poly1(bits);
	}
	#elif SECURITY_PARAM == 192
	poly_secpar_vec macs[192];
	for (size_t i = 0; i < 192; ++i) {
		macs[i] = qs_bits[i].mac;
	}
	out.mac = poly_secpar_from_secpar_poly_secpar(macs);
	if (!state->verifier)
	{
		poly1_vec bits[192];
		for (size_t i = 0; i < 192; ++i) {
			bits[i] = qs_bits[i].value;
		}
		out.value = poly_secpar_from_secpar_poly1(bits);
	}
	#elif SECURITY_PARAM == 256
	poly_secpar_vec macs[256];
	for (size_t i = 0; i < 256; ++i) {
		macs[i] = qs_bits[i].mac;
	}
	out.mac = poly_secpar_from_secpar_poly_secpar(macs);
	if (!state->verifier)
	{
		poly1_vec bits[256];
		for (size_t i = 0; i < 256; ++i) {
			bits[i] = qs_bits[i].value;
		}
		out.value = poly_secpar_from_secpar_poly1(bits);
	}
	#endif
	return out;
}

inline quicksilver_vec_gfsecpar quicksilver_combine_16_bits(const quicksilver_state* state, const quicksilver_vec_gf2* qs_bits)
{
	quicksilver_vec_gfsecpar out;

	poly_secpar_vec macs[16];
	for (size_t i = 0; i < 16; ++i)
		macs[i] = qs_bits[i].mac;
	out.mac = poly_secpar_from_16_poly_secpar(macs);

	if (!state->verifier)
	{
		poly1_vec bits[16];
		for (size_t i = 0; i < 16; ++i)
			bits[i] = qs_bits[i].value;
		out.value = poly_secpar_from_16_poly1(bits);
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

// NEW
// load secpar bit from s into QS GF(2) value, then combine it into a GF(2^secpar) value
// in the GF(2) subfield
inline quicksilver_vec_gfsecpar quicksilver_const_secpar_bits(const quicksilver_state* state, const void* s)
{
	#if SECURITY_PARAM == 128
	quicksilver_vec_gf2 input_bits[128];
    for (size_t bit_j = 0; bit_j < 128; ++bit_j) {
        input_bits[bit_j] = quicksilver_const_gf2(state, poly1_load(*((uint8_t*)s + (bit_j/8)), bit_j%8));
    }
	#elif SECURITY_PARAM == 192
	quicksilver_vec_gf2 input_bits[192];
    for (size_t bit_j = 0; bit_j < 192; ++bit_j) {
        input_bits[bit_j] = quicksilver_const_gf2(state, poly1_load(*((uint8_t*)s + (bit_j/8)), bit_j%8));
    }
	#elif SECURITY_PARAM == 256
	quicksilver_vec_gf2 input_bits[256];
    for (size_t bit_j = 0; bit_j < 256; ++bit_j) {
        input_bits[bit_j] = quicksilver_const_gf2(state, poly1_load(*((uint8_t*)s + (bit_j/8)), bit_j%8));
    }
	#endif
    return quicksilver_combine_secpar_bits(state, input_bits);
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

// NEW
// load secpar bits from the witness and combine it into a GF(2^secpar) value in the GF(2) subfield
inline quicksilver_vec_gfsecpar quicksilver_get_witness_secpar_bits(const quicksilver_state* state, size_t bit_index)
{
	#if SECURITY_PARAM == 128
	quicksilver_vec_gf2 input_bits[128];
    for (size_t bit_j = 0; bit_j < 128; ++bit_j) {
        input_bits[bit_j] = quicksilver_get_witness_vec(state, bit_index + bit_j);
    }
	#elif SECURITY_PARAM == 192
	quicksilver_vec_gf2 input_bits[192];
    for (size_t bit_j = 0; bit_j < 192; ++bit_j) {
        input_bits[bit_j] = quicksilver_get_witness_vec(state, bit_index + bit_j);
    }
	#elif SECURITY_PARAM == 256
	quicksilver_vec_gf2 input_bits[256];
    for (size_t bit_j = 0; bit_j < 256; ++bit_j) {
        input_bits[bit_j] = quicksilver_get_witness_vec(state, bit_index + bit_j);
    }
	#endif
    return quicksilver_combine_secpar_bits(state, input_bits);
}

// Add the constraint that a given degree 2 polynomial must be 0.
inline void quicksilver_constraint(quicksilver_state* state, quicksilver_vec_deg2 x)
{
	poly_secpar_vec const_term = poly_2secpar_reduce_secpar(x.mac0);

	if (state->verifier)
	{
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, const_term);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, const_term);
	}
	else
	{
		// Convert from polynomial evaluations to terms, similarly to Karatsuba. Assumes that the
		// constraint is valid, so plaintext value = evaluation at infinity = 0.
		poly_secpar_vec lin_term = poly_secpar_add(const_term, poly_2secpar_reduce_secpar(x.mac1));

		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, const_term);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, lin_term);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, const_term);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, lin_term);
	}
}

// Add the constraint x*y == 1.
inline void quicksilver_inverse_constraint(quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y)
{
	// assert(poly_secpar_eq(poly_2secpar_reduce_secpar(poly_secpar_mul(x.value, y.value)), poly_secpar_set_low32(1)));

	quicksilver_vec_deg2 mul = quicksilver_mul(state, x, y);
	quicksilver_vec_deg2 constraint = quicksilver_add_deg2(state, mul, quicksilver_one_deg2(state));
	quicksilver_constraint(state, constraint);
}

void quicksilver_prove(const quicksilver_state* restrict state, size_t witness_bits,
                       uint8_t* restrict proof, uint8_t* restrict check);
void quicksilver_verify(const quicksilver_state* restrict state, size_t witness_bits,
                        const uint8_t* restrict proof, uint8_t* restrict check);

#endif
