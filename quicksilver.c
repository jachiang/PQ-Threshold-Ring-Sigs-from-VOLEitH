#include "quicksilver.h"

#include <assert.h>
#include <stdio.h> // JC: for debugging.

// TODO: Figure out how to vectorize things here, for a later VAES implementation
static_assert(POLY_VEC_LEN == 1, "");

static void quicksilver_init_hash_keys(quicksilver_state* state, const uint8_t* challenge)
{
	for (size_t i = 0; i < 2; ++i, challenge += SECURITY_PARAM / 8)
		state->hash_combination[i] = poly_secpar_load_dup(challenge);
	poly_secpar_vec hash_key_secpar = poly_secpar_load_dup(challenge);
	poly64_vec hash_key_64 = poly64_load_dup(challenge + SECURITY_PARAM / 8);

	hasher_gfsecpar_init_key(&state->key_secpar, hash_key_secpar);
	hasher_gfsecpar_64_init_key(&state->key_64, hash_key_64);
}

void quicksilver_init_prover(
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

// JC: TODO - Update number of constraints
void quicksilver_init_or_prover(
	quicksilver_state* state, const uint8_t* witness, const block_secpar* macs,
	size_t num_owf_constraints, size_t num_ke_constraints, const uint8_t* challenge)
{
	state->verifier = false;

	// JC: initialize hash keys, which are reused by prover for both branch and final (ZK)hashes.
	quicksilver_init_hash_keys(state, challenge);
	// JC: init state of (ZK)Hash for batching constraints of each OR branch.
	size_t num_sbox_constraints = num_owf_constraints - num_ke_constraints;
	for (size_t branch = 0;  branch < FAEST_RING_SIZE; ++ branch){
		hasher_gfsecpar_init_state(&state->state_or_secpar_const[branch], num_sbox_constraints);
		hasher_gfsecpar_init_state(&state->state_or_secpar_linear[branch], num_sbox_constraints);
		hasher_gfsecpar_init_state(&state->state_or_secpar_quad[branch], num_sbox_constraints);
		hasher_gfsecpar_64_init_state(&state->state_or_64_const[branch], num_sbox_constraints);
		hasher_gfsecpar_64_init_state(&state->state_or_64_linear[branch], num_sbox_constraints);
		hasher_gfsecpar_64_init_state(&state->state_or_64_quad[branch], num_sbox_constraints);
	}
	// JC: Init state for final ZKHash state of KE and each (batched) OR branch constraint.
	hasher_gfsecpar_init_state(&state->state_secpar_const, num_ke_constraints + FAEST_RING_SIZE + 2);
	hasher_gfsecpar_init_state(&state->state_secpar_linear, num_ke_constraints + FAEST_RING_SIZE + 2);
	hasher_gfsecpar_init_state(&state->state_secpar_quad, num_ke_constraints + FAEST_RING_SIZE + 2);
	hasher_gfsecpar_64_init_state(&state->state_64_const, num_ke_constraints + FAEST_RING_SIZE + 2);
	hasher_gfsecpar_64_init_state(&state->state_64_linear, num_ke_constraints + FAEST_RING_SIZE + 2);
	hasher_gfsecpar_64_init_state(&state->state_64_quad, num_ke_constraints + FAEST_RING_SIZE + 2);

	state->witness = witness;
	state->macs = macs;
}

void quicksilver_init_verifier(
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

void quicksilver_init_or_verifier(
	quicksilver_state* state, const block_secpar* macs, size_t num_owf_constraints, size_t num_ke_constraints,
	block_secpar delta, const uint8_t* challenge)
{
	state->verifier = true;
	state->delta = poly_secpar_load_dup(&delta);
	state->deltaSq = poly_2secpar_reduce_secpar(poly_secpar_mul(state->delta, state->delta));

	quicksilver_init_hash_keys(state, challenge);

	size_t num_sbox_constraints = num_owf_constraints - num_ke_constraints;
	for (size_t branch = 0;  branch < FAEST_RING_SIZE; ++ branch){
		hasher_gfsecpar_init_state(&state->state_or_secpar_const[branch], num_sbox_constraints);
		hasher_gfsecpar_64_init_state(&state->state_or_64_const[branch], num_sbox_constraints);
	}

	hasher_gfsecpar_init_state(&state->state_secpar_const, num_ke_constraints + FAEST_RING_SIZE + 2);
	hasher_gfsecpar_64_init_state(&state->state_64_const, num_ke_constraints + FAEST_RING_SIZE + 2);

	state->macs = macs;
}

// JC: Non-ZK Hash of constraints stored to hasher states.
static poly_secpar_vec quicksilver_lincombine_hasher_state(
	const quicksilver_state* state,
	const hasher_gfsecpar_state* state_secpar, const hasher_gfsecpar_64_state* state_64)
{
	poly_secpar_vec hashes[2];
	hashes[0] = hasher_gfsecpar_final(state_secpar);
	hashes[1] = hasher_gfsecpar_64_final(state_64);

	poly_2secpar_vec sum = poly256_set_zero(); // JC: Set to zero, No mask required.
	for (size_t i = 0; i < 2; ++i)
		sum = poly_2secpar_add(sum, poly_secpar_mul(state->hash_combination[i], hashes[i]));

	return poly_2secpar_reduce_secpar(sum);
}

static void quicksilver_final(
	const quicksilver_state* state,
	const hasher_gfsecpar_state* state_secpar, const hasher_gfsecpar_64_state* state_64,
	poly_2secpar_vec mask, uint8_t* output)
{
	poly_secpar_vec hashes[2];
	hashes[0] = hasher_gfsecpar_final(state_secpar);
	hashes[1] = hasher_gfsecpar_64_final(state_64);

	poly_2secpar_vec sum = mask;
	for (size_t i = 0; i < 2; ++i)
		sum = poly_2secpar_add(sum, poly_secpar_mul(state->hash_combination[i], hashes[i]));

	poly_secpar_store1(output, poly_2secpar_reduce_secpar(sum));
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

void quicksilver_prove(const quicksilver_state* restrict state, size_t witness_bits,
                       uint8_t* restrict proof, uint8_t* restrict check)
{
	assert(!state->verifier);
	assert(witness_bits % 8 == 0);

	poly_2secpar_vec value_mask =
		poly_2secpar_from_secpar(poly_secpar_load_dup(&state->witness[witness_bits / 8]));
	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);

	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
	quicksilver_final(state, &state->state_secpar_linear, &state->state_64_linear, value_mask, proof);
}

void quicksilver_verify(const quicksilver_state* restrict state, size_t witness_bits,
                        const uint8_t* restrict proof, uint8_t* restrict check)
{
	assert(state->verifier);

	poly_secpar_vec linear_term = poly_secpar_load_dup(proof);

	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(linear_term, state->delta));
	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
}

void quicksilver_prove_or(quicksilver_state* state, size_t witness_bits,
                          uint8_t* restrict proof_quad, uint8_t* restrict proof_lin, uint8_t* restrict check)
{
	assert(!state->verifier);
	assert(witness_bits % 8 == 0);

	// JC: Assume witness_bits includes the hotvector encoding.
	// JC: TODO: Implement higher degree masks.
	poly_2secpar_vec zero_mask = poly256_set_zero();
	poly_2secpar_vec value_mask =
		poly_2secpar_from_secpar(poly_secpar_load_dup(&state->witness[witness_bits / 8]));
	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);

	poly_secpar_vec a1_secpar_selector_vec[FAEST_RING_SIZE];
	poly_secpar_vec a0_secpar_selector_vec[FAEST_RING_SIZE];

	poly_secpar_vec a1_secpar_selector_agg = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_selector_agg = poly_secpar_from_byte(0);

	poly_secpar_vec a1_secpar_selector_mul_idx_agg = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_selector_mul_idx_agg = poly_secpar_from_byte(0);

	uint32_t branch_loaded;
	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {

		// JC: Combine all constraints of each branch.
		poly_secpar_vec a0_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch],
												        &state->state_or_64_const[branch]);
		poly_secpar_vec a1_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_linear[branch],
														&state->state_or_64_linear[branch]);
		poly_secpar_vec a2_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_quad[branch],
														&state->state_or_64_quad[branch]);

		// JC: TODO - Derive last branch selector bit from running sum of prior branch selectors.
		// JC: TODO - remove this bit from witness / witness_bit parameters
		if (branch < FAEST_RING_SIZE - 1){
			// JC: Load branch selector bit commitment.
			quicksilver_vec_gf2	selector_bit = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + branch);
			a1_secpar_selector_vec[branch] = poly128_from_1(selector_bit.value);
			a0_secpar_selector_vec[branch] = selector_bit.mac;
		}
		else {
			// JC: Derive selector bit commitment from aggregate.
			a1_secpar_selector_vec[branch] = poly_secpar_add(poly_secpar_from_byte(1), a1_secpar_selector_agg);
			a0_secpar_selector_vec[branch] = a0_secpar_selector_agg;
		}
		// JC: Aggregate selector bits and selector multiplied by branch index.
		a1_secpar_selector_agg =  poly_secpar_add(a1_secpar_selector_agg, a1_secpar_selector_vec[branch]);
		a0_secpar_selector_agg =  poly_secpar_add(a0_secpar_selector_agg, a0_secpar_selector_vec[branch]);

		a1_secpar_selector_mul_idx_agg = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_selector_vec[branch],_mm_set1_epi32(branch + 1))),
													    a1_secpar_selector_mul_idx_agg);
		a0_secpar_selector_mul_idx_agg = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_selector_vec[branch],_mm_set1_epi32(branch + 1))),
														a0_secpar_selector_mul_idx_agg);

		// JC: Print - debugging active branch.
		bool selector_zero = poly128_eq(a1_secpar_selector_vec[branch], poly_secpar_from_byte(0));
		bool selector_one = poly128_eq(a1_secpar_selector_vec[branch], poly_secpar_from_byte(1));
		if (selector_one) {
			branch_loaded = branch;
		}
		// printf("Branch: %zu\n", branch);
		// printf("Selector bit = 0 %s\n", selector_zero ? "true" : "false");
		// printf("Selector bit = 1 %s\n", selector_one ? "true" : "false");

		// JC: Multiply committed selector bit with branch constraints.
		// JC: A3 = A2_branch * A1_selector (Assume zero).
		// JC: Print - debugging branch satisfaction.
		// poly_secpar_vec a3_secpar = poly_2secpar_reduce_secpar(
		// 							poly_secpar_mul(a2_secpar_branch, a1_secpar_selector_vec[branch]));
		// bool constraint_sat = poly128_eq(a3_secpar, poly_secpar_from_byte(0));
		// printf("Satisfied branch constraint %s\n", constraint_sat ? "true" : "false");

		// JC: A2 = A2_branch * A0_selector + A1_branch * A1_selector
		poly_secpar_vec a2_secpar = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a2_secpar_branch, a0_secpar_selector_vec[branch])),
													poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_branch, a1_secpar_selector_vec[branch])));
		// JC: A1 = A1_branch * A0_selector + A0_branch * A1_selector
		poly_secpar_vec a1_secpar = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_branch, a0_secpar_selector_vec[branch])),
												    poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_branch, a1_secpar_selector_vec[branch])));
		// JC: A0 = A0_branch * A0_selector
		poly_secpar_vec a0_secpar = poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_branch, a0_secpar_selector_vec[branch]));

		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, a0_secpar);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, a1_secpar);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, a2_secpar);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, a0_secpar);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, a1_secpar);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, a2_secpar);
	}
	printf("Active branch: %zu\n", branch_loaded);

	// JC: Well-formedness of hotvector (selector bits sum to 1).
	poly_secpar_vec a1_secpar_selector_wellformed = poly_secpar_add(a1_secpar_selector_agg, poly_secpar_from_byte(1));
	poly_secpar_vec a0_secpar_selector_wellformed = a0_secpar_selector_agg;

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, a0_secpar_selector_wellformed);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, a0_secpar_selector_wellformed);

	// JC: Well-formedness of hotvector (single active bit).
	poly_secpar_vec a2_secpar_selector_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a1_secpar_selector_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_selector_constr2 = poly_secpar_from_byte(0);

	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {
		poly_secpar_vec a1_secpar_tmp = poly_secpar_add(a1_secpar_selector_mul_idx_agg, _mm_set1_epi32(branch + 1));
		poly_secpar_vec a0_secpar_tmp = a0_secpar_selector_mul_idx_agg;

		a2_secpar_selector_constr2 = poly_secpar_add(a2_secpar_selector_constr2,
									 poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_tmp, a1_secpar_selector_vec[branch]))); // JC: zero - assume satisfied.
		a1_secpar_selector_constr2 = poly_secpar_add(a1_secpar_selector_constr2,
									 poly_secpar_add(
									 poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_tmp, a0_secpar_selector_vec[branch])),
									 poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_tmp, a1_secpar_selector_vec[branch]))));
		a0_secpar_selector_constr2 = poly_secpar_add(a0_secpar_selector_constr2,
									 poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_tmp, a0_secpar_selector_vec[branch])));
	}
	// bool constraint_sat = poly128_eq(a2_secpar_selector_constr2, poly_secpar_from_byte(0));
	// printf("Satisfied hotvector constraint %s\n", constraint_sat ? "true" : "false");

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, a0_secpar_selector_constr2);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, a1_secpar_selector_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, a0_secpar_selector_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, a1_secpar_selector_constr2);

	// JC: TODO - expand hasher state during init.

	// JC: Final ZKHash.
	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
	quicksilver_final(state, &state->state_secpar_linear, &state->state_64_linear, value_mask, proof_lin);
	quicksilver_final(state, &state->state_secpar_quad, &state->state_64_quad, zero_mask, proof_quad);
}

void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin, uint8_t* restrict check)
{
	assert(state->verifier);

	poly_secpar_vec key_selector_vec[FAEST_RING_SIZE];
	poly_secpar_vec key_selector_agg = poly_secpar_from_byte(0);
	poly_secpar_vec key_selector_mul_idx_agg = poly_secpar_from_byte(0);

	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {

		poly_secpar_vec key_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch],
												 &state->state_or_64_const[branch]);

		poly_secpar_vec key_selector;

		if (branch < FAEST_RING_SIZE - 1){
			key_selector = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + branch]);
		}
		else {
			key_selector = poly_secpar_add(key_selector_agg, state->delta);
		}
		key_selector_vec[branch] = key_selector;
		key_selector_agg = poly_secpar_add(key_selector, key_selector_agg);
		key_selector_mul_idx_agg = poly_secpar_add(key_selector_mul_idx_agg,
								   poly_2secpar_reduce_secpar(poly_secpar_mul(key_selector,_mm_set1_epi32(branch + 1))));

		poly_secpar_vec key_selector_mul_branch = poly_2secpar_reduce_secpar(poly_secpar_mul(key_branch, key_selector));
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_selector_mul_branch);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_selector_mul_branch);
	}

	// JC: Well-formedness of hotvector (selector bits sum to 1).
	poly_secpar_vec key_wellformed = poly_2secpar_reduce_secpar(poly_secpar_mul(poly_secpar_add(key_selector_agg, state->delta),state->deltaSq));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_wellformed);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_wellformed);

	// JC: Well-formedness of hotvector (single active bit).
    poly_secpar_vec key_constraint2 = poly_secpar_from_byte(0);
	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {
		poly_secpar_vec key_tmp = poly_secpar_add(key_selector_mul_idx_agg,
								  poly_2secpar_reduce_secpar(poly_secpar_mul(_mm_set1_epi32(branch + 1), state->delta)));
		key_constraint2 = poly_secpar_add(key_constraint2,
						 poly_2secpar_reduce_secpar(poly_secpar_mul(key_tmp, key_selector_vec[branch])));
	}

	// JC: TODO - bump up by one degree and add constraint to hasher state.
	key_constraint2 = poly_2secpar_reduce_secpar(poly_secpar_mul(key_constraint2, state->delta));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_constraint2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_constraint2);

	poly_secpar_vec linear_term = poly_secpar_load_dup(proof_lin);
	poly_secpar_vec quad_term = poly_secpar_load_dup(proof_quad);

	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);
	// poly_2secpar_vec mac_mask = poly256_set_zero();

	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(linear_term, state->delta));
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(quad_term, state->deltaSq));

	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
}

extern inline quicksilver_vec_gf2 quicksilver_get_witness_vec(const quicksilver_state* state, size_t index);
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
extern inline quicksilver_vec_gfsecpar quicksilver_const_8_bits(const quicksilver_state* state, const void* s);
extern inline quicksilver_vec_gfsecpar quicksilver_get_witness_8_bits(const quicksilver_state* state, size_t bit_index);
extern inline void quicksilver_add_product_constraints(quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y, bool ring);
extern inline void quicksilver_add_product_constraints_to_branch(quicksilver_state* state, size_t branch, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y);