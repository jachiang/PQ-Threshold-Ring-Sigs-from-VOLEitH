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

	qs_prover_poly_deg1 hotvec0[FAEST_RING_SIZE];

	qs_prover_poly_deg1 hotvecbit_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvecbit_sum);

	qs_prover_poly_deg1 hotvecbit_mul_idx_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvecbit_mul_idx_sum);

	uint32_t branch_loaded;
	for (uint16_t idx = 0; idx < FAEST_RING_HOTVECTOR_BITS + 1; ++idx) {
		if (idx < FAEST_RING_HOTVECTOR_BITS) {
			// JC: Load branch selector bit commitment.
			quicksilver_vec_gf2	hotvec_bit = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx);
			hotvec0[idx].c0 = hotvec_bit.mac;
			hotvec0[idx].c1 = poly128_from_1(hotvec_bit.value);
		}
		else {
			// JC: Derive final selector bit commitment from aggregate.
			hotvec0[idx] = qs_prover_poly_const_add_deg1(state, poly_secpar_from_byte(1), hotvecbit_sum);
		}
		// JC: Aggregate selector bits and selector multiplied by branch index.
		hotvecbit_sum = qs_prover_poly_deg1_add_deg1(state, hotvecbit_sum, hotvec0[idx]);
		hotvecbit_mul_idx_sum = qs_prover_poly_deg1_add_deg1(state, hotvecbit_mul_idx_sum, qs_prover_poly_const_mul_deg1(state, _mm_set1_epi32(idx + 1), hotvec0[idx]));
	}

	for (uint32_t branch = 0; branch < FAEST_RING_SIZE; branch++) {

		qs_prover_poly_deg2 branch_constraint;

		branch_constraint.c0 = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch],
												        &state->state_or_64_const[branch]);
		branch_constraint.c1 = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_linear[branch],
														&state->state_or_64_linear[branch]);
		branch_constraint.c2 = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_quad[branch],
														&state->state_or_64_quad[branch]);

		// JC: Print - debugging active branch.
		bool selector_one = poly128_eq(hotvec0[branch].c1, poly_secpar_from_byte(1));
		if (selector_one) {
			branch_loaded = branch;
		}

		qs_prover_poly_deg3 final_branch_constraint = qs_prover_poly_deg1_mul_deg2(state, hotvec0[branch], branch_constraint);

		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, final_branch_constraint.c0);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, final_branch_constraint.c1);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, final_branch_constraint.c2);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, final_branch_constraint.c0);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, final_branch_constraint.c1);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, final_branch_constraint.c2);
	}

	printf("Active branch loaded: %zu\n", branch_loaded);

	// JC: Well-formedness of hotvec (selector bits sum to 1).
	qs_prover_poly_deg1 sum_constraint = qs_prover_poly_const_add_deg1(state, poly_secpar_from_byte(1), hotvecbit_sum);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, sum_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, sum_constraint.c0);

	// JC: Well-formedness of hotvec (single active bit).
	qs_prover_poly_deg2 one_active_bit_constraint;
	quicksilver_prover_init_poly_deg2(state, &one_active_bit_constraint);
	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {
		qs_prover_poly_deg1 tmp = qs_prover_poly_const_add_deg1(state, _mm_set1_epi32(branch + 1), hotvecbit_mul_idx_sum);
		qs_prover_poly_deg2 tmp2 = qs_prover_poly_deg1_mul_deg1(state, tmp, hotvec0[branch]);
		one_active_bit_constraint = qs_prover_poly_deg2_add_deg2(state, one_active_bit_constraint, tmp2);
	}
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, one_active_bit_constraint.c0);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, one_active_bit_constraint.c1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, one_active_bit_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, one_active_bit_constraint.c1);

	// JC: Final ZKHash.
	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
	quicksilver_final(state, &state->state_secpar_linear, &state->state_64_linear, value_mask, proof_lin);
	quicksilver_final(state, &state->state_secpar_quad, &state->state_64_quad, zero_mask, proof_quad);
}

void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin, uint8_t* restrict check)
{
	assert(state->verifier);

	qs_verifier_key hotvec0[FAEST_RING_SIZE];
	qs_verifier_key hotvec0_sum;
	quicksilver_verifier_init_key_0(state, &hotvec0_sum);
	qs_verifier_key hotvec0_mul_idx_sum;
	quicksilver_verifier_init_key_0(state, &hotvec0_mul_idx_sum);

	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {

		qs_verifier_key branch_constraint;
		branch_constraint.key = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch], &state->state_or_64_const[branch]);
		branch_constraint.deg = 2;

		if (branch < FAEST_RING_SIZE - 1){
			hotvec0[branch].key = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + branch]);
			hotvec0[branch].deg = 1;
		}
		else {
			hotvec0[branch] = quicksilver_verifier_const_add_key(state, poly_secpar_from_byte(1), hotvec0_sum);
		}

		hotvec0_sum = quicksilver_verifier_key_add_key(state, hotvec0_sum, hotvec0[branch]);
		qs_verifier_key tmp	= quicksilver_verifier_const_mul_key(state, _mm_set1_epi32(branch + 1), hotvec0[branch]);
		hotvec0_mul_idx_sum = quicksilver_verifier_key_add_key(state, hotvec0_mul_idx_sum, tmp);

		qs_verifier_key final_branch_constraint = quicksilver_verifier_key_mul_key(state, hotvec0[branch], branch_constraint);

		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, final_branch_constraint.key);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, final_branch_constraint.key);
	}

	// JC: Well-formedness of hotvec (selector bits sum to 1).
	qs_verifier_key hotvec0_const1 = quicksilver_verifier_const_add_key(state, poly_secpar_from_byte(1), hotvec0_sum);
	quicksilver_verifier_increase_key_deg(state, &hotvec0_const1, 2);
	assert(hotvec0_const1.deg == 3);

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec0_const1.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec0_const1.key);

	// JC: Well-formedness of hotvec (single active bit).
	qs_verifier_key hotvec0_const2;
	quicksilver_verifier_init_key_0(state, &hotvec0_const2);

	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {
		qs_verifier_key tmp = quicksilver_verifier_const_add_key(state, _mm_set1_epi32(branch + 1), hotvec0_mul_idx_sum);
		tmp = quicksilver_verifier_key_mul_key(state, tmp, hotvec0[branch]);
		hotvec0_const2 = quicksilver_verifier_key_add_key(state, hotvec0_const2, tmp);
	}

	// JC: Bump up by one degree and add constraint to hasher state.
	quicksilver_verifier_increase_key_deg(state, &hotvec0_const2, 1);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec0_const2.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec0_const2.key);

	poly_secpar_vec linear_term = poly_secpar_load_dup(proof_lin);
	poly_secpar_vec quad_term = poly_secpar_load_dup(proof_quad);

	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);

	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(linear_term, state->delta));
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(quad_term, state->deltaSq));

	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
}

#elif (FAEST_RING_HOTVECTOR_DIM == 2)

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

	qs_prover_poly_deg1 hotvec0[FAEST_RING_HOTVECTOR_BITS + 1];
	qs_prover_poly_deg1 hotvec1[FAEST_RING_HOTVECTOR_BITS + 1];

	// JC: Sum_i hotvec0[i]
	poly_secpar_vec a1_secpar_hotvec0_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec0_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a1_secpar_hotvec1_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec1_sum = poly_secpar_from_byte(0);

	qs_prover_poly_deg1 hotvec0_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec0_sum);
	qs_prover_poly_deg1 hotvec1_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec1_sum);

	// JC: Sum_i hotvec0[i] * branch_idx
	poly_secpar_vec a1_secpar_hotvec0_mul_idx_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec0_mul_idx_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a1_secpar_hotvec1_mul_idx_sum = poly_secpar_from_byte(0);
	poly_secpar_vec a0_secpar_hotvec1_mul_idx_sum = poly_secpar_from_byte(0);

	qs_prover_poly_deg1 hotvec0_mul_idx_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec0_mul_idx_sum);
	qs_prover_poly_deg1 hotvec1_mul_idx_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec1_mul_idx_sum);

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

			hotvec0[idx].c1 = poly128_from_1(selector_bit0.value);
			hotvec0[idx].c0 = selector_bit0.mac;
			hotvec1[idx].c1 = poly128_from_1(selector_bit1.value);
			hotvec1[idx].c0 = selector_bit1.mac;
		}
		else {
			a1_secpar_hotvec0[idx] = poly_secpar_add(poly_secpar_from_byte(1), a1_secpar_hotvec0_sum);
			a0_secpar_hotvec0[idx] = a0_secpar_hotvec0_sum;
			a1_secpar_hotvec1[idx] = poly_secpar_add(poly_secpar_from_byte(1), a1_secpar_hotvec1_sum);
			a0_secpar_hotvec1[idx] = a0_secpar_hotvec1_sum;

			hotvec0[idx] = qs_prover_poly_const_add_deg1(state, poly_secpar_from_byte(1), hotvec0_sum);
			hotvec1[idx] = qs_prover_poly_const_add_deg1(state, poly_secpar_from_byte(1), hotvec1_sum);
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

		hotvec0_sum = qs_prover_poly_deg1_add_deg1(state, hotvec0_sum, hotvec0[idx]);
		hotvec0_mul_idx_sum = qs_prover_poly_deg1_add_deg1(state, hotvec0_mul_idx_sum, qs_prover_poly_const_mul_deg1(state, _mm_set1_epi32(idx + 1), hotvec0[idx]));

		if ( poly128_eq(a1_secpar_hotvec0[idx], poly_secpar_from_byte(1))) { idx0 = idx; }
		// else if (poly128_eq(a1_secpar_hotvec0[idx], poly_secpar_from_byte(0))) { printf("Hotvec0 0 entry at idx ... %u\n", idx); }
		if ( poly128_eq(a1_secpar_hotvec1[idx], poly_secpar_from_byte(1))) { idx1 = idx; }
		// else if (poly128_eq(a1_secpar_hotvec1[idx], poly_secpar_from_byte(0))) { printf("Hotvec1 0 entry at idx ... %u\n", idx); }
	}
	// bool test23 = poly128_eq(a1_secpar_hotvec0_mul_idx_sum, _mm_set1_epi32(1));
	// printf("Hotvec0 null; %s\n", test23 ? "true" : "false");
	// test23 = poly128_eq(a1_secpar_hotvec1_mul_idx_sum, _mm_set1_epi32(1));
	// printf("Hotvec1 null; %s\n", test23 ? "true" : "false");

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
		test = poly128_eq(a3_secpar, poly_secpar_from_byte(0));
		printf("a3_secpar is null?; %s\n", test ? "true" : "false");

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
		test = poly128_eq(a2_secpar, poly_secpar_from_byte(0));
		printf("a2_secpar is null?; %s\n", test ? "true" : "false");

		// JC: A1 = A1_hotvec0 * A0_hotvec1 * A0_branch +
		// 			A0_hotvec0 * A1_hotvec1 * A0_branch +
		// 			A0_hotvec0 * A0_hotvec0 * A1_branch
		poly_secpar_vec poly_ins0_c[3] = {a1_secpar_hotvec0[decomp[0]], a0_secpar_hotvec1[decomp[1]], a0_secpar_branch};
		poly_secpar_vec poly_ins1_c[3] = {a0_secpar_hotvec0[decomp[0]], a1_secpar_hotvec1[decomp[1]], a0_secpar_branch};
		poly_secpar_vec poly_ins2_c[3] = {a0_secpar_hotvec0[decomp[0]], a0_secpar_hotvec1[decomp[1]], a1_secpar_branch};
		poly_secpar_vec poly_ins_sum_c[3];
		poly_ins_sum_c[0] = poly_secpar_mul_many(poly_ins0_c, 3);
		poly_ins_sum_c[1] = poly_secpar_mul_many(poly_ins1_c, 3);
		poly_ins_sum_c[2] = poly_secpar_mul_many(poly_ins2_c, 3);
		poly_secpar_vec a1_secpar = poly_secpar_add_many(poly_ins_sum_c, 3);
		test = poly128_eq(a1_secpar, poly_secpar_from_byte(0));
		printf("a1_secpar is null?; %s\n", test ? "true" : "false");

		// JC: A0 = A0_hotvec0 * A0_hotvec1 * A0_branch
		poly_secpar_vec poly_ins0_d[3] = {a0_secpar_hotvec0[decomp[0]], a0_secpar_hotvec1[decomp[1]], a0_secpar_branch};
		poly_secpar_vec a0_secpar = poly_secpar_mul_many(poly_ins0_d, 3);
		test = poly128_eq(a0_secpar, poly_secpar_from_byte(0));
		printf("a0_secpar is null?; %s\n", test ? "true" : "false");

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
		bool constraint_sat0 = poly128_eq(a0_secpar_hotvec0_constr2, poly_secpar_from_byte(0));
		printf("Null element? %s\n", constraint_sat0 ? "true" : "false");

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

	poly_secpar_vec key_hotvec0[FAEST_RING_HOTVECTOR_BITS+1];
	poly_secpar_vec key_hotvec1[FAEST_RING_HOTVECTOR_BITS+1];
	poly_secpar_vec key_hotvec0_sum = poly_secpar_from_byte(0);
	poly_secpar_vec key_hotvec1_sum = poly_secpar_from_byte(0);
	poly_secpar_vec key_hotvec0_mul_idx_sum = poly_secpar_from_byte(0);
	poly_secpar_vec key_hotvec1_mul_idx_sum = poly_secpar_from_byte(0);

	// JC: Load hotvectors.
	for (uint32_t idx = 0; idx <FAEST_RING_HOTVECTOR_BITS+1; ++idx) {
		if (idx < FAEST_RING_HOTVECTOR_BITS){
			key_hotvec0[idx] = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx]);
			key_hotvec1[idx] = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + FAEST_RING_HOTVECTOR_BITS + idx]);
		}
		else {
			key_hotvec0[idx] = poly_secpar_add(key_hotvec0_sum, state->delta);
			key_hotvec1[idx] = poly_secpar_add(key_hotvec1_sum, state->delta);
		}
		// JC: Derive hotvector aggregates (for well-formedness constraints).
		key_hotvec0_sum = poly_secpar_add(key_hotvec0[idx], key_hotvec0_sum);
		key_hotvec0_mul_idx_sum = poly_secpar_add(key_hotvec0_mul_idx_sum,
								  poly_2secpar_reduce_secpar(poly_secpar_mul(key_hotvec0[idx],_mm_set1_epi32(idx + 1))));
		key_hotvec1_sum = poly_secpar_add(key_hotvec1[idx], key_hotvec1_sum);
		key_hotvec1_mul_idx_sum = poly_secpar_add(key_hotvec1_mul_idx_sum,
								  poly_2secpar_reduce_secpar(poly_secpar_mul(key_hotvec1[idx],_mm_set1_epi32(idx + 1))));
	}

	// JC: Derive branch constraints.
	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; ++branch) {

		poly_secpar_vec key_branch = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch], &state->state_or_64_const[branch]);

		// JC: Decompose branch idx into (i,j).
		uint32_t base = FAEST_RING_HOTVECTOR_BITS + 1;
		uint32_t decomp[2] = {0};
		base_decompose(branch, base, decomp, FAEST_RING_HOTVECTOR_DIM);
		printf("Verifier hotvec0 idx: %u\n", decomp[0]);
		printf("Verifier hotvec1 idx: %u\n", decomp[1]);

		poly_secpar_vec key_hotvec_bits_mul_branch = poly_2secpar_reduce_secpar(poly_secpar_mul(key_branch,
													 poly_2secpar_reduce_secpar(poly_secpar_mul(key_hotvec0[decomp[0]], key_hotvec1[decomp[1]]))));

		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_hotvec_bits_mul_branch);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_hotvec_bits_mul_branch);
	}

	// JC: Well-formedness of hotvec (selector bits sum to 1).
	poly_secpar_vec key_hotvec0_constr1 = poly_2secpar_reduce_secpar(poly_secpar_mul(state->delta,
										  poly_2secpar_reduce_secpar(poly_secpar_mul(poly_secpar_add(key_hotvec0_sum, state->delta),state->deltaSq))));
	poly_secpar_vec key_hotvec1_constr1 = poly_2secpar_reduce_secpar(poly_secpar_mul(state->delta,
										  poly_2secpar_reduce_secpar(poly_secpar_mul(poly_secpar_add(key_hotvec1_sum, state->delta),state->deltaSq))));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_hotvec0_constr1);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_hotvec1_constr1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_hotvec0_constr1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_hotvec1_constr1);

	// JC: Well-formedness of hotvec (single active bit).
    poly_secpar_vec key_hotvec0_constr2 = poly_secpar_from_byte(0);
    poly_secpar_vec key_hotvec1_constr2 = poly_secpar_from_byte(0);
	for (uint32_t idx = 0; idx <FAEST_RING_HOTVECTOR_BITS+1; ++idx) {
		poly_secpar_vec key_tmp0 = poly_secpar_add(key_hotvec0_mul_idx_sum,
								  poly_2secpar_reduce_secpar(poly_secpar_mul(_mm_set1_epi32(idx + 1), state->delta)));
		key_hotvec0_constr2 = poly_secpar_add(key_hotvec0_constr2,
						 poly_2secpar_reduce_secpar(poly_secpar_mul(key_tmp0, key_hotvec0[idx])));
		poly_secpar_vec key_tmp1 = poly_secpar_add(key_hotvec0_mul_idx_sum,
								  poly_2secpar_reduce_secpar(poly_secpar_mul(_mm_set1_epi32(idx + 1), state->delta)));
		key_hotvec1_constr2 = poly_secpar_add(key_hotvec1_constr2,
						 poly_2secpar_reduce_secpar(poly_secpar_mul(key_tmp1, key_hotvec1[idx])));
	}

	// JC: Bump up by two degrees, add constraint to hasher state.
	key_hotvec0_constr2 = poly_2secpar_reduce_secpar(poly_secpar_mul(key_hotvec0_constr2, state->deltaSq));
	key_hotvec1_constr2 = poly_2secpar_reduce_secpar(poly_secpar_mul(key_hotvec1_constr2, state->deltaSq));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_hotvec0_constr2);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, key_hotvec1_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_hotvec0_constr2);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, key_hotvec1_constr2);

	poly_secpar_vec linear_term = poly_secpar_load_dup(proof_lin);
	poly_secpar_vec quad_term = poly_secpar_load_dup(proof_quad);
	poly_secpar_vec cubic_term = poly_secpar_load_dup(proof_cubic);

	poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);
	// poly_2secpar_vec mac_mask = poly256_set_zero();

	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(linear_term, state->delta));
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(quad_term, state->deltaSq));
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(state->delta, poly_2secpar_reduce_secpar(poly_secpar_mul(cubic_term, state->deltaSq))));

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