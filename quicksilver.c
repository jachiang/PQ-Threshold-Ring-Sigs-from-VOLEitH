#include "quicksilver.h"

// TODO: Some things are unvectorized here.
static_assert(POLY_VEC_LEN == 1);

static block_secpar compute_universal_hash(
	const quicksilver_state* state,
	const hasher_gfsecpar_state* state_secpar, const hasher_gfsecpar_64_state* state_64,
	poly_2secpar_vec mask)
{
	poly_secpar_vec hashes[2];
	hashes[0] = hasher_gfsecpar_final(state_secpar);
	hashes[1] = hasher_gfsecpar_64_final(state_64);

	poly_2secpar_vec sum = mask;
	for (size_t i = 0; i < 2; ++i)
		sum = poly_2secpar_add(sum, poly_secpar_mul(state->hash_combination[i], hashes[i]));

	block_secpar output;
	poly_secpar_store1(&output, poly_2secpar_reduce_secpar(sum));
	return output;
}

// Output in vector index 0.
static poly_2secpar_vec combine_mask_macs(const quicksilver_state* state, size_t witness_bits)
{
	poly_2secpar_vec accumulators[8 / POLY_VEC_LEN];

	for (int j = 0; j < 8 / POLY_VEC_LEN; ++j)
	{
		poly_secpar_vec x =
			poly_secpar_load(&state->macs[witness_bits + SECURITY_PARAM - 8 + POLY_VEC_LEN * j]);
		accumulators[j] = poly_2secpar_from_secpar(x);
	}

	for (int i = SECURITY_PARAM - 16; i >= 0; i -= 8)
	{
		for (int j = 0; j < 8 / POLY_VEC_LEN; ++j)
		{
			poly_secpar_vec x = poly_secpar_load(&state->macs[witness_bits + i + POLY_VEC_LEN * j]);
			accumulators[j] = poly_2secpar_add(poly_2secpar_shift_left_8(accumulators[j]),
			                                   poly_2secpar_from_secpar(x));
		}
	}

	poly_2secpar_vec total;
	memset(&total, 0, sizeof(total));
	for (int j = 8 / POLY_VEC_LEN - 1; j >= 0; --j)
	{
		for (int k = POLY_VEC_LEN - 1; k >= 0; --k)
		{
			total = poly_2secpar_shift_left_1(total);
			total = poly_2secpar_add(total, poly_2secpar_extract(accumulators[j], k));
		}
	}

	return total;
}

void quicksilver_prove(const quicksilver_state* state, size_t witness_bits, uint8_t* proof)
{
	assert(!state->verifier);
	assert(witness_bits % 8 == 0);

	poly_2secpar_vec value_mask =
		poly_2secpar_from_secpar(poly_secpar_load_dup(&state->witness[witness_bits / 8]));
	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);

	block_secpar check_const = compute_universal_hash(
		state, &state->state_secpar_const, &state->state_64_const, mac_mask);
	block_secpar check_linear = compute_universal_hash(
		state, &state->state_secpar_linear, &state->state_64_linear, value_mask);

	// TODO
}

bool quicksilver_verify(const quicksilver_state* state, size_t witness_bits, const uint8_t* proof)
{
	assert(state->verifier);

	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);
	block_secpar check_const = compute_universal_hash(
		state, &state->state_secpar_const, &state->state_64_const, mac_mask);

	// TODO
	return true;
}

extern inline void quicksilver_init_hash_keys(quicksilver_state* state, const uint8_t* challenge);
extern inline void quicksilver_init_prover(
    quicksilver_state* state, const uint8_t* witness, const block_secpar* macs,
    size_t num_constraints, const uint8_t* challenge);
extern inline void quicksilver_init_verifier(
    quicksilver_state* state, const block_secpar* macs, size_t num_constraints,
    block_secpar delta, const uint8_t* challenge);
extern inline quicksilver_vec_gf2 quicksilver_get_witness_vec(const quicksilver_state* state, size_t index);
extern inline void quicksilver_final(const quicksilver_state* state, bool verifier,
        poly_secpar_vec* hash_const_secpar, poly_secpar_vec* hash_linear_secpar,
        poly_secpar_vec* hash_const_64, poly_secpar_vec* hash_linear_64);
extern inline poly_secpar_vec quicksilver_get_delta(const quicksilver_state* state);
extern inline quicksilver_vec_gf2 quicksilver_add_gf2(const quicksilver_state* state, quicksilver_vec_gf2 x, quicksilver_vec_gf2 y);
extern inline quicksilver_vec_gfsecpar quicksilver_add_gfsecpar(const quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y);
extern inline quicksilver_vec_gf2 quicksilver_zero_gf2();
extern inline quicksilver_vec_gfsecpar quicksilver_zero_gfsecpar();
extern inline quicksilver_vec_gf2 quicksilver_one_gf2(const quicksilver_state* state);
extern inline quicksilver_vec_gfsecpar quicksilver_one_gfsecpar(const quicksilver_state* state);
extern inline quicksilver_vec_gf2 quicksilver_const_gf2(const quicksilver_state* state, poly1_vec c);
extern inline quicksilver_vec_gfsecpar quicksilver_const_gfsecpar(const quicksilver_state* state, poly_secpar_vec c);
extern inline quicksilver_vec_gf2 quicksilver_mul_const_gf2(const quicksilver_state* state, quicksilver_vec_gf2 x, poly1_vec c);
extern inline quicksilver_vec_gfsecpar quicksilver_mul_const(const quicksilver_state* state, quicksilver_vec_gfsecpar x, poly_secpar_vec c);
extern inline quicksilver_vec_gfsecpar quicksilver_combine_8_bits(const quicksilver_state* state, const quicksilver_vec_gf2* qs_bits);
extern inline void quicksilver_add_product_constraints(quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y);
