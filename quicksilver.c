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
	// JC: Ring number of branch constraints, 2 constraints for wellformedness for each hotvector.
	hasher_gfsecpar_init_state(&state->state_secpar_const, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	hasher_gfsecpar_init_state(&state->state_secpar_linear, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	hasher_gfsecpar_init_state(&state->state_secpar_quad, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	hasher_gfsecpar_64_init_state(&state->state_64_const, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	hasher_gfsecpar_64_init_state(&state->state_64_linear, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	hasher_gfsecpar_64_init_state(&state->state_64_quad, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hasher_gfsecpar_init_state(&state->state_secpar_cubic, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	hasher_gfsecpar_64_init_state(&state->state_64_cubic, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	#endif

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

	hasher_gfsecpar_init_state(&state->state_secpar_const, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);
	hasher_gfsecpar_64_init_state(&state->state_64_const, num_ke_constraints + FAEST_RING_SIZE + 2 * FAEST_RING_HOTVECTOR_DIM);

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

#if (FAEST_RING_HOTVECTOR_DIM == 1)

void quicksilver_prove_or(quicksilver_state* state, size_t witness_bits,
                          uint8_t* restrict proof_quad, uint8_t* restrict proof_lin, uint8_t* restrict check)
{
	assert(!state->verifier);
	assert(witness_bits % 8 == 0);

	// JC: TODO: Implement higher degree masks.
	poly_2secpar_vec zero_mask = poly256_set_zero();
	poly_2secpar_vec value_mask = poly_2secpar_from_secpar(poly_secpar_load_dup(&state->witness[witness_bits / 8]));
	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);

	poly_secpar_vec a1_secpar_selector_vec[FAEST_RING_SIZE];
	poly_secpar_vec a0_secpar_selector_vec[FAEST_RING_SIZE];

	poly_secpar_vec a1_secpar_selector_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_selector_sum = poly_secpar_from_byte(0);

	poly_secpar_vec a1_secpar_selector_mul_idx_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_selector_mul_idx_sum = poly_secpar_from_byte(0);

	uint32_t branch_loaded;
	for (uint32_t branch = 0; branch < FAEST_RING_SIZE; branch++) {

		// JC: Combine all constraints of each branch.
		poly_secpar_vec a0_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch],
												        &state->state_or_64_const[branch]);
		poly_secpar_vec a1_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_linear[branch],
														&state->state_or_64_linear[branch]);
		poly_secpar_vec a2_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_quad[branch],
														&state->state_or_64_quad[branch]);

		if (branch < FAEST_RING_SIZE - 1){
			// JC: Load branch selector bit commitment.
			quicksilver_vec_gf2	selector_bit = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + branch);
			a1_secpar_selector_vec[branch] = poly128_from_1(selector_bit.value);
			a0_secpar_selector_vec[branch] = selector_bit.mac;
		}
		else {
			// JC: Derive final selector bit commitment from aggregate.
			a1_secpar_selector_vec[branch] = poly_secpar_add(poly_secpar_from_byte(1), a1_secpar_selector_sum);
			a0_secpar_selector_vec[branch] = a0_secpar_selector_sum;
		}

		// JC: Aggregate selector bits and selector multiplied by branch index.
		a1_secpar_selector_sum =  poly_secpar_add(a1_secpar_selector_sum, a1_secpar_selector_vec[branch]);
		a0_secpar_selector_sum =  poly_secpar_add(a0_secpar_selector_sum, a0_secpar_selector_vec[branch]);

		a1_secpar_selector_mul_idx_sum = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_selector_vec[branch],_mm_set1_epi32(branch + 1))), a1_secpar_selector_mul_idx_sum);
		a0_secpar_selector_mul_idx_sum = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_selector_vec[branch],_mm_set1_epi32(branch + 1))), a0_secpar_selector_mul_idx_sum);

		// JC: Print - debugging active branch.
		bool selector_zero = poly128_eq(a1_secpar_selector_vec[branch], poly_secpar_from_byte(0));
		bool selector_one = poly128_eq(a1_secpar_selector_vec[branch], poly_secpar_from_byte(1));
		if (selector_one) {
			branch_loaded = branch;
		}
		// printf("Branch: %zu\n", branch);
		// printf("Selector bit = 0 %s\n", selector_zero ? "true" : "false");
		// printf("Selector bit = 1 %s\n", selector_one ? "true" : "false");

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

	printf("Active branch loaded: %zu\n", branch_loaded);

	// JC: Well-formedness of hotvec (selector bits sum to 1).
	poly_secpar_vec a1_secpar_selector_constr1 = poly_secpar_add(a1_secpar_selector_sum, poly_secpar_from_byte(1));
	poly_secpar_vec a0_secpar_selector_constr1 = a0_secpar_selector_sum;

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, a0_secpar_selector_constr1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, a0_secpar_selector_constr1);

	// JC: Well-formedness of hotvec (single active bit).
	poly_secpar_vec a2_secpar_selector_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a1_secpar_selector_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_selector_constr2 = poly_secpar_from_byte(0);

	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {
		poly_secpar_vec a1_secpar_tmp = poly_secpar_add(a1_secpar_selector_mul_idx_sum, _mm_set1_epi32(branch + 1));
		poly_secpar_vec a0_secpar_tmp = a0_secpar_selector_mul_idx_sum;

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
	// printf("Satisfied hotvec constraint %s\n", constraint_sat ? "true" : "false");

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, a0_secpar_selector_constr2);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, a1_secpar_selector_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, a0_secpar_selector_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, a1_secpar_selector_constr2);

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
	poly_secpar_vec key_selector_sum = poly_secpar_from_byte(0);
	poly_secpar_vec key_selector_mul_idx_sum = poly_secpar_from_byte(0);

	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {

		poly_secpar_vec key_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch],
												 &state->state_or_64_const[branch]);

		poly_secpar_vec key_selector;

		if (branch < FAEST_RING_SIZE - 1){
			key_selector = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + branch]);
		}
		else {
			key_selector = poly_secpar_add(key_selector_sum, state->delta);
		}
		key_selector_vec[branch] = key_selector;
		key_selector_sum = poly_secpar_add(key_selector, key_selector_sum);
		key_selector_mul_idx_sum = poly_secpar_add(key_selector_mul_idx_sum,
								   poly_2secpar_reduce_secpar(poly_secpar_mul(key_selector,_mm_set1_epi32(branch + 1))));

		poly_secpar_vec key_selector_mul_branch = poly_2secpar_reduce_secpar(poly_secpar_mul(key_branch, key_selector));
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_selector_mul_branch);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_selector_mul_branch);
	}

	// JC: Well-formedness of hotvec (selector bits sum to 1).
	poly_secpar_vec key_constr1 = poly_2secpar_reduce_secpar(poly_secpar_mul(poly_secpar_add(key_selector_sum, state->delta),state->deltaSq));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_constr1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_constr1);

	// JC: Well-formedness of hotvec (single active bit).
    poly_secpar_vec key_constraint2 = poly_secpar_from_byte(0);
	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {
		poly_secpar_vec key_tmp = poly_secpar_add(key_selector_mul_idx_sum,
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

#else

void quicksilver_prove_or(quicksilver_state* state, size_t witness_bits, uint8_t* restrict proof_cubic,
                          uint8_t* restrict proof_quad, uint8_t* restrict proof_lin, uint8_t* restrict check)
{
	assert(!state->verifier);
	assert(witness_bits % 8 == 0);

	// JC: TODO: Implement higher degree masks.
	poly_2secpar_vec zero_mask = poly256_set_zero();
	poly_2secpar_vec value_mask =
		poly_2secpar_from_secpar(poly_secpar_load_dup(&state->witness[witness_bits / 8]));
	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);

	// JC: 2 hotvecs.
	poly_secpar_vec a1_secpar_hotvec0[FAEST_RING_HOTVECTOR_BITS + 1]; // JC: TODO - Initiate on heap.
	poly_secpar_vec a0_secpar_hotvec0[FAEST_RING_HOTVECTOR_BITS + 1];
	poly_secpar_vec a1_secpar_hotvec1[FAEST_RING_HOTVECTOR_BITS + 1];
	poly_secpar_vec a0_secpar_hotvec1[FAEST_RING_HOTVECTOR_BITS + 1];

	// JC: Sum_i hotvec[i]
	poly_secpar_vec a1_secpar_hotvec0_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec0_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a1_secpar_hotvec1_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec1_sum = poly_secpar_from_byte(0);

	// JC: Sum_i hotvec[i] * branch_idx
	poly_secpar_vec a1_secpar_hotvec0_mul_idx_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec0_mul_idx_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a1_secpar_hotvec1_mul_idx_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec1_mul_idx_sum = poly_secpar_from_byte(0);

	// JC: Test correct decomposition;
	uint32_t idx0 = 0;
	uint32_t idx1 = 0;

	for (uint16_t idx = 0; idx < FAEST_RING_HOTVECTOR_BITS + 1; ++idx) {
		if (idx < FAEST_RING_HOTVECTOR_BITS) {
			// JC: Load hotvec bits.
			quicksilver_vec_gf2	selector_bit0 = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx);
			quicksilver_vec_gf2	selector_bit1 = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx + FAEST_RING_HOTVECTOR_BITS);
			a1_secpar_hotvec0[idx] = poly128_from_1(selector_bit0.value);
			a0_secpar_hotvec0[idx] = selector_bit0.mac;
			a1_secpar_hotvec1[idx] = poly128_from_1(selector_bit1.value);
			a0_secpar_hotvec1[idx] = selector_bit1.mac;
		}
		else {
			a1_secpar_hotvec0[idx] = poly_secpar_add(poly_secpar_from_byte(1), a1_secpar_hotvec0_sum);
			a0_secpar_hotvec0[idx] = a0_secpar_hotvec0_sum;
			a1_secpar_hotvec1[idx] = poly_secpar_add(poly_secpar_from_byte(1), a1_secpar_hotvec1_sum);
			a0_secpar_hotvec1[idx] = a0_secpar_hotvec1_sum;
		}
		// JC: Aggregate selector bits
		a1_secpar_hotvec0_sum =  poly_secpar_add(a1_secpar_hotvec0_sum, a1_secpar_hotvec0[idx]);
		a0_secpar_hotvec0_sum =  poly_secpar_add(a0_secpar_hotvec0_sum, a0_secpar_hotvec0[idx]);
		a1_secpar_hotvec1_sum =  poly_secpar_add(a1_secpar_hotvec1_sum, a1_secpar_hotvec1[idx]);
		a0_secpar_hotvec1_sum =  poly_secpar_add(a0_secpar_hotvec1_sum, a0_secpar_hotvec1[idx]);
		// JC: Aggregate selector bit multiplied by branch index.
		a1_secpar_hotvec0_mul_idx_sum = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_hotvec0[idx],_mm_set1_epi32(idx + 1))), a1_secpar_hotvec0_mul_idx_sum);
		a0_secpar_hotvec0_mul_idx_sum = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_hotvec0[idx],_mm_set1_epi32(idx + 1))), a0_secpar_hotvec0_mul_idx_sum);
		a1_secpar_hotvec1_mul_idx_sum = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_hotvec1[idx],_mm_set1_epi32(idx + 1))), a1_secpar_hotvec1_mul_idx_sum);
		a0_secpar_hotvec1_mul_idx_sum = poly_secpar_add(poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_hotvec1[idx],_mm_set1_epi32(idx + 1))), a0_secpar_hotvec1_mul_idx_sum);

		if ( poly128_eq(a1_secpar_hotvec0[idx], poly_secpar_from_byte(1))) { idx0 = idx; }
		// else if (poly128_eq(a1_secpar_hotvec0[idx], poly_secpar_from_byte(0))) { printf("Hotvec0 0 entry at idx ... %u\n", idx); }
		if ( poly128_eq(a1_secpar_hotvec1[idx], poly_secpar_from_byte(1))) { idx1 = idx; }
		// else if (poly128_eq(a1_secpar_hotvec1[idx], poly_secpar_from_byte(0))) { printf("Hotvec1 0 entry at idx ... %u\n", idx); }
	}
	// JC: Test active bit;
	printf("Active hotvec 0 idx %u\n", idx0);
	printf("Active hotvec 1 idx %u\n", idx1);

	// JC: Derive branch constraints.
	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {

		poly_secpar_vec a0_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch],
												        &state->state_or_64_const[branch]);
		poly_secpar_vec a1_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_linear[branch],
														&state->state_or_64_linear[branch]);
		poly_secpar_vec a2_secpar_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_quad[branch],
														&state->state_or_64_quad[branch]);

		// JC: Decompose branch idx into (i,j).
		uint32_t base = FAEST_RING_HOTVECTOR_BITS + 1;
		uint32_t decomp[FAEST_RING_HOTVECTOR_DIM] = {0};
		base_decompose(branch, base, decomp, FAEST_RING_HOTVECTOR_DIM);

		// JC: Final branch constraint: hotvec0[i] x hotvec1[j] x [branch]
		// JC: A4 = A1_hotvec0 * A1_hotvec1 * A2_branch (Assume 0, constraint holds).
		poly_secpar_vec poly_ins0[3] = {a1_secpar_hotvec0[decomp[0]], a1_secpar_hotvec1[decomp[1]], a2_secpar_branch};
		poly_secpar_vec a4_secpar = poly_secpar_mul_many(poly_ins0, 3);
		bool test = poly128_eq(a4_secpar, poly_secpar_from_byte(0));
		printf("Branch constraint satisfied; %s\n", test ? "true" : "false");

		// JC: A3 = A1_hotvec0 * A1_hotvec1 * A1_branch +
		// 			A1_hotvec0 * A0_hotvec1 * A2_branch +
		// 			A0_hotvec0 * A1_hotvec1 * A2_branch
		poly_secpar_vec poly_ins0_a[3] = {a1_secpar_hotvec0[decomp[0]], a1_secpar_hotvec1[decomp[1]], a1_secpar_branch};
		poly_secpar_vec poly_ins1_a[3] = {a1_secpar_hotvec0[decomp[0]], a0_secpar_hotvec1[decomp[1]], a2_secpar_branch};
		poly_secpar_vec poly_ins2_a[3] = {a0_secpar_hotvec0[decomp[0]], a1_secpar_hotvec1[decomp[1]], a2_secpar_branch};
		poly_secpar_vec poly_ins_sum_a[3];
		poly_ins_sum_a[0] = poly_secpar_mul_many(poly_ins0_a, 3);
		poly_ins_sum_a[1] = poly_secpar_mul_many(poly_ins1_a, 3);
		poly_ins_sum_a[2] = poly_secpar_mul_many(poly_ins2_a, 3);
		poly_secpar_vec a3_secpar = poly_secpar_add_many(poly_ins_sum_a, 3);

		// JC: A2 = A1_hotvec0 * A1_hotvec1 * A0_branch +
		// 			A1_hotvec0 * A0_hotvec1 * A1_branch +
		// 			A0_hotvec0 * A1_hotvec1 * A1_branch +
		// 			A0_hotvec0 * A0_hotvec1 * A2_branch
		poly_secpar_vec poly_ins0_b[3] = {a1_secpar_hotvec0[decomp[0]], a1_secpar_hotvec1[decomp[1]], a0_secpar_branch};
		poly_secpar_vec poly_ins1_b[3] = {a1_secpar_hotvec0[decomp[0]], a0_secpar_hotvec1[decomp[1]], a1_secpar_branch};
		poly_secpar_vec poly_ins2_b[3] = {a0_secpar_hotvec0[decomp[0]], a1_secpar_hotvec1[decomp[1]], a1_secpar_branch};
		poly_secpar_vec poly_ins3_b[3] = {a0_secpar_hotvec0[decomp[0]], a0_secpar_hotvec1[decomp[1]], a2_secpar_branch};
		poly_secpar_vec poly_ins_sum_b[4];
		poly_ins_sum_b[0] = poly_secpar_mul_many(poly_ins0_b, 3);
		poly_ins_sum_b[1] = poly_secpar_mul_many(poly_ins1_b, 3);
		poly_ins_sum_b[2] = poly_secpar_mul_many(poly_ins2_b, 3);
		poly_ins_sum_b[3] = poly_secpar_mul_many(poly_ins3_b, 3);
		poly_secpar_vec a2_secpar = poly_secpar_add_many(poly_ins_sum_b, 4);

		// JC: A1 = A1_hotvec0 * A0_hotvec1 * A0_branch +
		// 			A0_hotvec0 * A1_hotvec1 * A0_branch +
		// 			A0_hotvec0 * A1_hotvec0 * A0_branch
		poly_secpar_vec poly_ins0_c[3] = {a1_secpar_hotvec0[decomp[0]], a0_secpar_hotvec1[decomp[1]], a0_secpar_branch};
		poly_secpar_vec poly_ins1_c[3] = {a0_secpar_hotvec0[decomp[0]], a1_secpar_hotvec1[decomp[1]], a0_secpar_branch};
		poly_secpar_vec poly_ins2_c[3] = {a0_secpar_hotvec0[decomp[0]], a1_secpar_hotvec1[decomp[1]], a0_secpar_branch};
		poly_secpar_vec poly_ins_sum_c[3];
		poly_ins_sum_c[0] = poly_secpar_mul_many(poly_ins0_c, 3);
		poly_ins_sum_c[1] = poly_secpar_mul_many(poly_ins1_c, 3);
		poly_ins_sum_c[2] = poly_secpar_mul_many(poly_ins2_c, 3);
		poly_secpar_vec a1_secpar = poly_secpar_add_many(poly_ins_sum_c, 3);

		// JC: A0 = A0_hotvec0 * A0_hotvec1 * A0_branch
		poly_secpar_vec poly_ins0_d[3] = {a0_secpar_hotvec0[decomp[0]], a0_secpar_hotvec1[decomp[1]], a0_secpar_branch};
		poly_secpar_vec a0_secpar = poly_secpar_mul_many(poly_ins0_d, 3);

		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, a0_secpar);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, a1_secpar);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, a2_secpar);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, a3_secpar);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, a0_secpar);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, a1_secpar);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, a2_secpar);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, a3_secpar);
	}

	// JC: Well-formedness of hotvecs (selector bits sum to 1, deg-1 term presumed zero).
	poly_secpar_vec a1_secpar_hotvec0_constr1 = poly_secpar_add(a1_secpar_hotvec0_sum, poly_secpar_from_byte(1));
	poly_secpar_vec a0_secpar_hotvec0_constr1 = a0_secpar_hotvec0_sum;
	poly_secpar_vec a1_secpar_hotvec1_constr1 = poly_secpar_add(a1_secpar_hotvec1_sum, poly_secpar_from_byte(1));
	poly_secpar_vec a0_secpar_hotvec1_constr1 = a0_secpar_hotvec1_sum;

	bool test1 = poly128_eq(a1_secpar_hotvec0_constr1, poly_secpar_from_byte(0));
	printf("Sum to 1, hotvec 0 %s\n", test1 ? "true" : "false");
	bool test2 = poly128_eq(a1_secpar_hotvec1_constr1, poly_secpar_from_byte(0));
	printf("Sum to 1, hotvec 1 %s\n", test2 ? "true" : "false");

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, a0_secpar_hotvec0_constr1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, a0_secpar_hotvec0_constr1);

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, a0_secpar_hotvec1_constr1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, a0_secpar_hotvec1_constr1);

	// JC: Well-formedness of hotvecs (single active bit).
	poly_secpar_vec a2_secpar_hotvec0_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a1_secpar_hotvec0_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec0_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a2_secpar_hotvec1_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a1_secpar_hotvec1_constr2 = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec1_constr2 = poly_secpar_from_byte(0);

	for (uint32_t idx = 0; idx <FAEST_RING_HOTVECTOR_BITS+1; idx++) {
		poly_secpar_vec a1_secpar_tmp_0 = poly_secpar_add(a1_secpar_hotvec0_mul_idx_sum, _mm_set1_epi32(idx + 1));
		poly_secpar_vec a0_secpar_tmp_0 = a0_secpar_hotvec0_mul_idx_sum;

		poly_secpar_vec a1_secpar_tmp_1 = poly_secpar_add(a1_secpar_hotvec1_mul_idx_sum, _mm_set1_epi32(idx + 1));
		poly_secpar_vec a0_secpar_tmp_1 = a0_secpar_hotvec1_mul_idx_sum;

		// JC: TODO - assume satisified. For debugging.
		a2_secpar_hotvec0_constr2 = poly_secpar_add(a2_secpar_hotvec0_constr2,
									  poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_tmp_0, a1_secpar_hotvec0[idx])));
		a1_secpar_hotvec0_constr2 = poly_secpar_add(a1_secpar_hotvec0_constr2,
									  poly_secpar_add(
									  poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_tmp_0, a0_secpar_hotvec0[idx])),
									  poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_tmp_0, a1_secpar_hotvec0[idx]))));
		a0_secpar_hotvec0_constr2 = poly_secpar_add(a0_secpar_hotvec0_constr2,
									  poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_tmp_0, a0_secpar_hotvec0[idx])));
		// JC: TODO - assume satisified. For debugging.
		a2_secpar_hotvec1_constr2 = poly_secpar_add(a2_secpar_hotvec1_constr2,
									  poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_tmp_1, a1_secpar_hotvec1[idx])));
		a1_secpar_hotvec1_constr2 = poly_secpar_add(a1_secpar_hotvec1_constr2,
									  poly_secpar_add(
									  poly_2secpar_reduce_secpar(poly_secpar_mul(a1_secpar_tmp_1, a0_secpar_hotvec1[idx])),
									  poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_tmp_1, a1_secpar_hotvec1[idx]))));
		a0_secpar_hotvec1_constr2 = poly_secpar_add(a0_secpar_hotvec1_constr2,
									  poly_2secpar_reduce_secpar(poly_secpar_mul(a0_secpar_tmp_1, a0_secpar_hotvec1[idx])));
	}
	bool constraint_sat0 = poly128_eq(a2_secpar_hotvec0_constr2, poly_secpar_from_byte(0));
	printf("Single active bit, hotvec 0: %s\n", constraint_sat0 ? "true" : "false");

	bool constraint_sat1 = poly128_eq(a2_secpar_hotvec1_constr2, poly_secpar_from_byte(0));
	printf("Single active bit, hotvec 1: %s\n", constraint_sat1 ? "true" : "false");

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, a0_secpar_hotvec0_constr2);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, a1_secpar_hotvec0_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, a0_secpar_hotvec0_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, a1_secpar_hotvec0_constr2);

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, a0_secpar_hotvec1_constr2);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, a1_secpar_hotvec1_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, a0_secpar_hotvec1_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, a1_secpar_hotvec1_constr2);

	// JC: Final ZKHash.
	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
	quicksilver_final(state, &state->state_secpar_linear, &state->state_64_linear, value_mask, proof_lin);
	quicksilver_final(state, &state->state_secpar_quad, &state->state_64_quad, zero_mask, proof_quad);
	quicksilver_final(state, &state->state_secpar_cubic, &state->state_64_cubic, zero_mask, proof_cubic);
}

void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits, const uint8_t* restrict proof_cubic,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin, uint8_t* restrict check)
{
	assert(state->verifier);

	poly_secpar_vec key_selector_vec[FAEST_RING_SIZE];
	poly_secpar_vec key_selector_sum = poly_secpar_from_byte(0);
	poly_secpar_vec key_selector_mul_idx_sum = poly_secpar_from_byte(0);

	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {

		poly_secpar_vec key_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch],
												 &state->state_or_64_const[branch]);

		poly_secpar_vec key_selector;

		if (branch < FAEST_RING_SIZE - 1){
			key_selector = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + branch]);
		}
		else {
			key_selector = poly_secpar_add(key_selector_sum, state->delta);
		}
		key_selector_vec[branch] = key_selector;
		key_selector_sum = poly_secpar_add(key_selector, key_selector_sum);
		key_selector_mul_idx_sum = poly_secpar_add(key_selector_mul_idx_sum,
								   poly_2secpar_reduce_secpar(poly_secpar_mul(key_selector,_mm_set1_epi32(branch + 1))));

		poly_secpar_vec key_selector_mul_branch = poly_2secpar_reduce_secpar(poly_secpar_mul(key_branch, key_selector));
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_selector_mul_branch);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_selector_mul_branch);
	}

	// JC: Well-formedness of hotvec (selector bits sum to 1).
	poly_secpar_vec key_constr1 = poly_2secpar_reduce_secpar(poly_secpar_mul(poly_secpar_add(key_selector_sum, state->delta),state->deltaSq));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_constr1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_constr1);

	// JC: Well-formedness of hotvec (single active bit).
    poly_secpar_vec key_constraint2 = poly_secpar_from_byte(0);
	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {
		poly_secpar_vec key_tmp = poly_secpar_add(key_selector_mul_idx_sum,
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

#endif

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