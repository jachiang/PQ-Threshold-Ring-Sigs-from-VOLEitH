#include "quicksilver.h"
#include "owf_proof.h"

#include <assert.h>
#include <stdalign.h>
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
	state->ring = false;

	quicksilver_init_hash_keys(state, challenge);
	hasher_gfsecpar_init_state(&state->state_secpar_const, num_constraints);
	hasher_gfsecpar_init_state(&state->state_secpar_linear, num_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_const, num_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_linear, num_constraints);

	state->witness = witness;
	state->macs = macs;
}

void quicksilver_init_verifier(
	quicksilver_state* state, const block_secpar* macs, size_t num_constraints,
	block_secpar delta, const uint8_t* challenge)
{
	state->verifier = true;
	state->ring = false;
	state->delta = poly_secpar_load_dup(&delta);
	state->deltaSq = poly_2secpar_reduce_secpar(poly_secpar_mul(state->delta, state->delta));

	quicksilver_init_hash_keys(state, challenge);
	hasher_gfsecpar_init_state(&state->state_secpar_const, num_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_const, num_constraints);

	state->macs = macs;
}

void quicksilver_init_or_prover(
	quicksilver_state* state, const uint8_t* witness, const block_secpar* macs, const uint8_t* challenge, bool tag)
{
	state->verifier = false;
	state->ring = true;

	// JC: initialize hash keys, which are reused by prover for both branch and final (ZK)hashes.
	quicksilver_init_hash_keys(state, challenge);
	// JC: init state of (ZK)Hash for batching constraints of each OR branch.
	state->state_or_secpar_const = (hasher_gfsecpar_state *)aligned_alloc(alignof(hasher_gfsecpar_state), FAEST_RING_SIZE * sizeof(hasher_gfsecpar_state));
	state->state_or_secpar_linear = (hasher_gfsecpar_state *)aligned_alloc(alignof(hasher_gfsecpar_state), FAEST_RING_SIZE * sizeof(hasher_gfsecpar_state));
	state->state_or_secpar_quad = (hasher_gfsecpar_state *)aligned_alloc(alignof(hasher_gfsecpar_state), FAEST_RING_SIZE * sizeof(hasher_gfsecpar_state));
	state->state_or_64_const = (hasher_gfsecpar_64_state *)aligned_alloc(alignof(hasher_gfsecpar_state), FAEST_RING_SIZE * sizeof(hasher_gfsecpar_64_state));
	state->state_or_64_linear = (hasher_gfsecpar_64_state *)aligned_alloc(alignof(hasher_gfsecpar_state), FAEST_RING_SIZE * sizeof(hasher_gfsecpar_64_state));
	state->state_or_64_quad = (hasher_gfsecpar_64_state *)aligned_alloc(alignof(hasher_gfsecpar_state), FAEST_RING_SIZE * sizeof(hasher_gfsecpar_64_state));

	assert(state->state_or_secpar_const != NULL);
	assert(state->state_or_secpar_linear != NULL);
	assert(state->state_or_secpar_quad != NULL);
	assert(state->state_or_64_const != NULL);
	assert(state->state_or_64_linear != NULL);
	assert(state->state_or_64_quad != NULL);

	for (size_t branch = 0;  branch < FAEST_RING_SIZE; ++ branch){
		size_t branch_constraints;
		if (!tag) {
			branch_constraints = ENC_SCHEDULE_CONSTRAINTS;
		}
		else{
			branch_constraints = ENC_SCHEDULE_CONSTRAINTS * TAGGED_RING_PK_OWF_NUM;
		}
		hasher_gfsecpar_init_state(&state->state_or_secpar_const[branch], branch_constraints);
		hasher_gfsecpar_init_state(&state->state_or_secpar_linear[branch], branch_constraints);
		hasher_gfsecpar_init_state(&state->state_or_secpar_quad[branch], branch_constraints);
		hasher_gfsecpar_64_init_state(&state->state_or_64_const[branch], branch_constraints);
		hasher_gfsecpar_64_init_state(&state->state_or_64_linear[branch], branch_constraints);
		hasher_gfsecpar_64_init_state(&state->state_or_64_quad[branch], branch_constraints);
	}

	size_t final_constraints;
	if (!tag) {
		final_constraints = OWF_KEY_SCHEDULE_CONSTRAINTS + FAEST_RING_SIZE + FAEST_RING_HOTVECTOR_DIM;
	}
	else {
		// TODO: Update TAGGED_RING_PK_OWF_NUM to tag owf constraint count.
		final_constraints = OWF_KEY_SCHEDULE_CONSTRAINTS + ENC_SCHEDULE_CONSTRAINTS * TAGGED_RING_PK_OWF_NUM + FAEST_RING_SIZE + FAEST_RING_HOTVECTOR_DIM;
	}
	hasher_gfsecpar_init_state(&state->state_secpar_const, final_constraints);
	hasher_gfsecpar_init_state(&state->state_secpar_linear, final_constraints);
	hasher_gfsecpar_init_state(&state->state_secpar_quad, final_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_const, final_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_linear, final_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_quad, final_constraints);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hasher_gfsecpar_init_state(&state->state_secpar_cubic, final_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_cubic, final_constraints);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hasher_gfsecpar_init_state(&state->state_secpar_quartic, final_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_quartic, final_constraints);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hasher_gfsecpar_init_state(&state->state_secpar_quintic, final_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_quintic, final_constraints);
	#endif

	state->witness = witness;
	state->macs = macs;
}

void quicksilver_init_or_verifier(
	quicksilver_state* state, const block_secpar* macs, block_secpar delta, const uint8_t* challenge, bool tag)
{
	state->verifier = true;
	state->ring = true;

	state->delta = poly_secpar_load_dup(&delta);
	state->deltaSq = poly_2secpar_reduce_secpar(poly_secpar_mul(state->delta, state->delta));

	quicksilver_init_hash_keys(state, challenge);

	state->state_or_secpar_const = (hasher_gfsecpar_state *)aligned_alloc(alignof(hasher_gfsecpar_state), FAEST_RING_SIZE * sizeof(hasher_gfsecpar_state));
	state->state_or_64_const = (hasher_gfsecpar_64_state *)aligned_alloc(alignof(hasher_gfsecpar_state), FAEST_RING_SIZE * sizeof(hasher_gfsecpar_64_state));

	assert(state->state_or_secpar_const != NULL);
	assert(state->state_or_64_const != NULL);

	for (size_t branch = 0;  branch < FAEST_RING_SIZE; ++ branch){
		size_t branch_constraints;
		if (!tag) {
			branch_constraints = ENC_SCHEDULE_CONSTRAINTS;
		}
		else{
			branch_constraints = ENC_SCHEDULE_CONSTRAINTS * TAGGED_RING_PK_OWF_NUM;
		}
		hasher_gfsecpar_init_state(&state->state_or_secpar_const[branch], branch_constraints);
		hasher_gfsecpar_64_init_state(&state->state_or_64_const[branch], branch_constraints);
	}

	size_t final_constraints;
	if (!tag) {
		final_constraints = OWF_KEY_SCHEDULE_CONSTRAINTS + FAEST_RING_SIZE + FAEST_RING_HOTVECTOR_DIM;
	}
	else{
		// TODO: Update TAGGED_RING_PK_OWF_NUM to tag owf constraint count.
		final_constraints = OWF_KEY_SCHEDULE_CONSTRAINTS + ENC_SCHEDULE_CONSTRAINTS * TAGGED_RING_PK_OWF_NUM + FAEST_RING_SIZE + FAEST_RING_HOTVECTOR_DIM;
	}
	hasher_gfsecpar_init_state(&state->state_secpar_const, final_constraints);
	hasher_gfsecpar_64_init_state(&state->state_64_const, final_constraints);

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

	poly_2secpar_vec sum = poly_2secpar_set_zero(); // JC: Set to zero, No mask required.
	for (size_t i = 0; i < 2; ++i) {
		sum = poly_2secpar_add(sum, poly_secpar_mul(state->hash_combination[i], hashes[i]));
	}
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
#elif (FAEST_RING_HOTVECTOR_DIM == 2)
void quicksilver_prove_or(quicksilver_state* state, size_t witness_bits, uint8_t* restrict proof_cubic,
                          uint8_t* restrict proof_quad, uint8_t* restrict proof_lin, uint8_t* restrict check)
#elif (FAEST_RING_HOTVECTOR_DIM == 4)
void quicksilver_prove_or(quicksilver_state* state, size_t witness_bits, uint8_t* restrict proof_quintic,
						  uint8_t* restrict proof_quartic, uint8_t* restrict proof_cubic,
                          uint8_t* restrict proof_quad, uint8_t* restrict proof_lin, uint8_t* restrict check)
#endif
{
	assert(!state->verifier);
	assert(witness_bits % 8 == 0);

	// JC: TODO: Implement higher degree masks.
	qs_prover_poly_deg1 mask1;
	qs_prover_poly_deg2 mask2;
	quicksilver_prover_init_poly_deg1(state, &mask1);
	quicksilver_prover_init_poly_deg2(state, &mask2);
	mask1.c0 = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits));
	mask1.c1 = poly_secpar_load_dup(&state->witness[witness_bits / 8]);
	mask2.c1 = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits + SECURITY_PARAM));
	mask2.c2 = poly_secpar_load_dup(&state->witness[(witness_bits + SECURITY_PARAM) / 8]);
	qs_prover_poly_deg2 qs_mask12 = qs_prover_poly_deg1_add_deg2(state, mask1, mask2);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	qs_prover_poly_deg3 mask3;
	quicksilver_prover_init_poly_deg3(state, &mask3);
	mask3.c2 = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits + 2*SECURITY_PARAM));
	mask3.c3 = poly_secpar_load_dup(&state->witness[(witness_bits + 2*SECURITY_PARAM) / 8]);
	qs_prover_poly_deg3 qs_mask123 = qs_prover_poly_deg2_add_deg3(state, qs_mask12, mask3);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	qs_prover_poly_deg4 mask4;
	quicksilver_prover_init_poly_deg4(state, &mask4);
	mask4.c3 = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits + 3*SECURITY_PARAM));
	mask4.c4 = poly_secpar_load_dup(&state->witness[(witness_bits + 3*SECURITY_PARAM) / 8]);
	qs_prover_poly_deg4 qs_mask1234 = qs_prover_poly_deg3_add_deg4(state, qs_mask123, mask4);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	qs_prover_poly_deg5 mask5;
	quicksilver_prover_init_poly_deg5(state, &mask5);
	mask5.c4 = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits + 4*SECURITY_PARAM));
	mask5.c5 = poly_secpar_load_dup(&state->witness[(witness_bits + 4*SECURITY_PARAM) / 8]);
	qs_prover_poly_deg5 qs_mask12345 = qs_prover_poly_deg4_add_deg5(state, qs_mask1234, mask5);
	#endif

	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	// poly_2secpar_vec zero_mask = poly_2secpar_set_zero();
	// poly_2secpar_vec value_mask = poly_2secpar_from_secpar(poly_secpar_load_dup(&state->witness[witness_bits / 8]));
	// poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);
	poly_2secpar_vec mask_c0 = poly_2secpar_from_secpar(qs_mask12.c0);
	poly_2secpar_vec mask_c1 = poly_2secpar_from_secpar(qs_mask12.c1);
	poly_2secpar_vec mask_c2 = poly_2secpar_from_secpar(qs_mask12.c2);
	#elif (FAEST_RING_HOTVECTOR_DIM == 2)
	poly_2secpar_vec mask_c0 = poly_2secpar_from_secpar(qs_mask123.c0);
	poly_2secpar_vec mask_c1 = poly_2secpar_from_secpar(qs_mask123.c1);
	poly_2secpar_vec mask_c2 = poly_2secpar_from_secpar(qs_mask123.c2);
	poly_2secpar_vec mask_c3 = poly_2secpar_from_secpar(qs_mask123.c3);
	#elif (FAEST_RING_HOTVECTOR_DIM == 4)
	poly_2secpar_vec mask_c0 = poly_2secpar_from_secpar(qs_mask12345.c0);
	poly_2secpar_vec mask_c1 = poly_2secpar_from_secpar(qs_mask12345.c1);
	poly_2secpar_vec mask_c2 = poly_2secpar_from_secpar(qs_mask12345.c2);
	poly_2secpar_vec mask_c3 = poly_2secpar_from_secpar(qs_mask12345.c3);
	poly_2secpar_vec mask_c4 = poly_2secpar_from_secpar(qs_mask12345.c4);
	poly_2secpar_vec mask_c5 = poly_2secpar_from_secpar(qs_mask12345.c5);
	#endif

	qs_prover_poly_deg1* hotvec0;
	size_t vec_size = (FAEST_RING_HOTVECTOR_BITS+1) * sizeof(qs_prover_poly_deg1);
    hotvec0 = (qs_prover_poly_deg1 *)aligned_alloc(alignof(qs_prover_poly_deg1), vec_size);
    assert(hotvec0 != NULL);
	qs_prover_poly_deg1 hotvec0_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec0_sum);
	qs_prover_poly_deg1 hotvec0_mul_idx_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec0_mul_idx_sum);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	qs_prover_poly_deg1* hotvec1;
	hotvec1 = (qs_prover_poly_deg1 *)aligned_alloc(alignof(qs_prover_poly_deg1), vec_size);
    assert(hotvec1 != NULL);
	qs_prover_poly_deg1 hotvec1_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec1_sum);
	qs_prover_poly_deg1 hotvec1_mul_idx_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec1_mul_idx_sum);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	qs_prover_poly_deg1* hotvec2;
	hotvec2 = (qs_prover_poly_deg1 *)aligned_alloc(alignof(qs_prover_poly_deg1), vec_size);
    assert(hotvec2 != NULL);
	qs_prover_poly_deg1 hotvec2_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec2_sum);
	qs_prover_poly_deg1 hotvec2_mul_idx_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec2_mul_idx_sum);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	qs_prover_poly_deg1* hotvec3;
	hotvec3 = (qs_prover_poly_deg1 *)aligned_alloc(alignof(qs_prover_poly_deg1), vec_size);
    assert(hotvec3 != NULL);
	qs_prover_poly_deg1 hotvec3_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec3_sum);
	qs_prover_poly_deg1 hotvec3_mul_idx_sum;
	quicksilver_prover_init_poly_deg1(state, &hotvec3_mul_idx_sum);
	#endif

	for (uint16_t idx = 0; idx < FAEST_RING_HOTVECTOR_BITS + 1; ++idx) {
		if (idx < FAEST_RING_HOTVECTOR_BITS) {
			// JC: Load branch selector bit commitment.
			quicksilver_vec_gf2	hotvec0_bit = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx);
			hotvec0[idx].c0 = hotvec0_bit.mac;
			hotvec0[idx].c1 = poly_secpar_from_1(hotvec0_bit.value);
			#if (FAEST_RING_HOTVECTOR_DIM > 1)
			quicksilver_vec_gf2	hotvec1_bit = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx + FAEST_RING_HOTVECTOR_BITS);
			hotvec1[idx].c0 = hotvec1_bit.mac;
			hotvec1[idx].c1 = poly_secpar_from_1(hotvec1_bit.value);
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 2)
			quicksilver_vec_gf2	hotvec2_bit = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx + 2*FAEST_RING_HOTVECTOR_BITS);
			hotvec2[idx].c0 = hotvec2_bit.mac;
			hotvec2[idx].c1 = poly_secpar_from_1(hotvec2_bit.value);
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 3)
			quicksilver_vec_gf2	hotvec3_bit = quicksilver_get_witness_vec(state, witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx + 3*FAEST_RING_HOTVECTOR_BITS);
			hotvec3[idx].c0 = hotvec3_bit.mac;
			hotvec3[idx].c1 = poly_secpar_from_1(hotvec3_bit.value);
			#endif
		}
		else {
			// JC: Derive final selector bit commitment from aggregate.
			hotvec0[idx] = qs_prover_poly_const_add_deg1(state, poly_secpar_from_byte(1), hotvec0_sum);
			#if (FAEST_RING_HOTVECTOR_DIM > 1)
			hotvec1[idx] = qs_prover_poly_const_add_deg1(state, poly_secpar_from_byte(1), hotvec1_sum);
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 2)
			hotvec2[idx] = qs_prover_poly_const_add_deg1(state, poly_secpar_from_byte(1), hotvec2_sum);
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 3)
			hotvec3[idx] = qs_prover_poly_const_add_deg1(state, poly_secpar_from_byte(1), hotvec3_sum);
			#endif
		}
		// JC: Aggregate selector bits and selector multiplied by branch index.
		hotvec0_sum = qs_prover_poly_deg1_add_deg1(state, hotvec0_sum, hotvec0[idx]);
		hotvec0_mul_idx_sum = qs_prover_poly_deg1_add_deg1(state, hotvec0_mul_idx_sum, qs_prover_poly_const_mul_deg1(state, poly_secpar_from_1(idx + 1), hotvec0[idx]));
		#if (FAEST_RING_HOTVECTOR_DIM > 1)
		hotvec1_sum = qs_prover_poly_deg1_add_deg1(state, hotvec1_sum, hotvec1[idx]);
		hotvec1_mul_idx_sum = qs_prover_poly_deg1_add_deg1(state, hotvec1_mul_idx_sum, qs_prover_poly_const_mul_deg1(state, poly_secpar_from_1(idx + 1), hotvec1[idx]));
		#endif
		#if (FAEST_RING_HOTVECTOR_DIM > 2)
		hotvec2_sum = qs_prover_poly_deg1_add_deg1(state, hotvec2_sum, hotvec2[idx]);
		hotvec2_mul_idx_sum = qs_prover_poly_deg1_add_deg1(state, hotvec2_mul_idx_sum, qs_prover_poly_const_mul_deg1(state, poly_secpar_from_1(idx + 1), hotvec2[idx]));
		#endif
		#if (FAEST_RING_HOTVECTOR_DIM > 3)
		hotvec3_sum = qs_prover_poly_deg1_add_deg1(state, hotvec3_sum, hotvec3[idx]);
		hotvec3_mul_idx_sum = qs_prover_poly_deg1_add_deg1(state, hotvec3_mul_idx_sum, qs_prover_poly_const_mul_deg1(state, poly_secpar_from_1(idx + 1), hotvec3[idx]));
		#endif
	}

	for (uint32_t branch = 0; branch < FAEST_RING_SIZE; branch++) {

		qs_prover_poly_deg2 branch_constraint;

		branch_constraint.c0 = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch],
												        &state->state_or_64_const[branch]);
		branch_constraint.c1 = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_linear[branch],
														&state->state_or_64_linear[branch]);
		branch_constraint.c2 = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_quad[branch],
														&state->state_or_64_quad[branch]);

		// bool branch_sat = poly128_eq(branch_constraint.c2, poly_secpar_from_byte(0));
		// if (branch_sat) {
		// 	printf("Sat branch index: %u\n", branch);
		// }

		uint32_t base = FAEST_RING_HOTVECTOR_BITS + 1;
		uint32_t decomp[FAEST_RING_HOTVECTOR_DIM] = {0};
		base_decompose(branch, base, decomp, FAEST_RING_HOTVECTOR_DIM);

		#if (FAEST_RING_HOTVECTOR_DIM == 1)
		qs_prover_poly_deg3 final_branch_constraint = qs_prover_poly_deg1_mul_deg2(state, hotvec0[decomp[0]], branch_constraint);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, final_branch_constraint.c0);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, final_branch_constraint.c1);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, final_branch_constraint.c2);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, final_branch_constraint.c0);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, final_branch_constraint.c1);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, final_branch_constraint.c2);

		#elif (FAEST_RING_HOTVECTOR_DIM == 2)
		qs_prover_poly_deg2 selector = qs_prover_poly_deg1_mul_deg1(state, hotvec0[decomp[0]], hotvec1[decomp[1]]);
		qs_prover_poly_deg4 final_branch_constraint = qs_prover_poly_deg2_mul_deg2(state, branch_constraint, selector);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, final_branch_constraint.c0);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, final_branch_constraint.c1);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, final_branch_constraint.c2);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, final_branch_constraint.c3);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, final_branch_constraint.c0);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, final_branch_constraint.c1);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, final_branch_constraint.c2);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, final_branch_constraint.c3);

		#elif (FAEST_RING_HOTVECTOR_DIM == 4)
		qs_prover_poly_deg2 tmp0 = qs_prover_poly_deg1_mul_deg1(state, hotvec0[decomp[0]], hotvec1[decomp[1]]);
		qs_prover_poly_deg2 tmp1 = qs_prover_poly_deg1_mul_deg1(state, hotvec2[decomp[2]], hotvec3[decomp[3]]);
		qs_prover_poly_deg4 selector = qs_prover_poly_deg2_mul_deg2(state, tmp0, tmp1);
		// bool not_selected = poly128_eq(selector.c4, poly_secpar_from_byte(0));
		// if (!not_selected) {
		// 	printf("Loaded index: %u\n", branch);
		// }
		qs_prover_poly_deg6 final_branch_constraint = qs_prover_poly_deg2_mul_deg4(state, branch_constraint, selector);

		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, final_branch_constraint.c0);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, final_branch_constraint.c1);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, final_branch_constraint.c2);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, final_branch_constraint.c3);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quartic, final_branch_constraint.c4);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quintic, final_branch_constraint.c5);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, final_branch_constraint.c0);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, final_branch_constraint.c1);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, final_branch_constraint.c2);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, final_branch_constraint.c3);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quartic, final_branch_constraint.c4);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quintic, final_branch_constraint.c5);
		#endif
	}

	// JC: Well-formedness of hotvec (single active bit).
	qs_prover_poly_deg2 hotvec0_single_active_bit_constraint;
	quicksilver_prover_init_poly_deg2(state, &hotvec0_single_active_bit_constraint);

	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	qs_prover_poly_deg2 hotvec1_single_active_bit_constraint;
	quicksilver_prover_init_poly_deg2(state, &hotvec1_single_active_bit_constraint);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	qs_prover_poly_deg2 hotvec2_single_active_bit_constraint;
	quicksilver_prover_init_poly_deg2(state, &hotvec2_single_active_bit_constraint);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	qs_prover_poly_deg2 hotvec3_single_active_bit_constraint;
	quicksilver_prover_init_poly_deg2(state, &hotvec3_single_active_bit_constraint);
	#endif

	for (uint32_t idx = 0; idx <FAEST_RING_HOTVECTOR_BITS + 1; idx++) {
		qs_prover_poly_deg1 tmp00 = qs_prover_poly_const_add_deg1(state, poly_secpar_from_1(idx + 1), hotvec0_mul_idx_sum);
		qs_prover_poly_deg2 tmp01 = qs_prover_poly_deg1_mul_deg1(state, tmp00, hotvec0[idx]);
		hotvec0_single_active_bit_constraint = qs_prover_poly_deg2_add_deg2(state, hotvec0_single_active_bit_constraint, tmp01);

		#if (FAEST_RING_HOTVECTOR_DIM > 1)
		qs_prover_poly_deg1 tmp10 = qs_prover_poly_const_add_deg1(state, poly_secpar_from_1(idx + 1), hotvec1_mul_idx_sum);
		qs_prover_poly_deg2 tmp11 = qs_prover_poly_deg1_mul_deg1(state, tmp10, hotvec1[idx]);
		hotvec1_single_active_bit_constraint = qs_prover_poly_deg2_add_deg2(state, hotvec1_single_active_bit_constraint, tmp11);
		#endif
		#if (FAEST_RING_HOTVECTOR_DIM > 2)
		qs_prover_poly_deg1 tmp20 = qs_prover_poly_const_add_deg1(state, poly_secpar_from_1(idx + 1), hotvec2_mul_idx_sum);
		qs_prover_poly_deg2 tmp21 = qs_prover_poly_deg1_mul_deg1(state, tmp20, hotvec2[idx]);
		hotvec2_single_active_bit_constraint = qs_prover_poly_deg2_add_deg2(state, hotvec2_single_active_bit_constraint, tmp21);
		#endif
		#if (FAEST_RING_HOTVECTOR_DIM > 3)
		qs_prover_poly_deg1 tmp30 = qs_prover_poly_const_add_deg1(state, poly_secpar_from_1(idx + 1), hotvec3_mul_idx_sum);
		qs_prover_poly_deg2 tmp31 = qs_prover_poly_deg1_mul_deg1(state, tmp30, hotvec3[idx]);
		hotvec3_single_active_bit_constraint = qs_prover_poly_deg2_add_deg2(state, hotvec3_single_active_bit_constraint, tmp31);
		#endif
	}

	free(hotvec0);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	free(hotvec1);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	free(hotvec2);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	free(hotvec3);
	#endif

	// bool sat0 = poly128_eq(hotvec0_single_active_bit_constraint.c2, poly_secpar_from_byte(0));
	// bool sat1 = poly128_eq(hotvec1_single_active_bit_constraint.c2, poly_secpar_from_byte(0));
	// bool sat2 = poly128_eq(hotvec2_single_active_bit_constraint.c2, poly_secpar_from_byte(0));
	// bool sat3 = poly128_eq(hotvec3_single_active_bit_constraint.c2, poly_secpar_from_byte(0));
	// printf("Hotvec0 constraint:: %s\n", sat0 ? "true" : "false");
	// printf("Hotvec1 constraint:: %s\n", sat1 ? "true" : "false");
	// printf("Hotvec2 constraint:: %s\n", sat2 ? "true" : "false");
	// printf("Hotvec3 constraint:: %s\n", sat3 ? "true" : "false");

	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, hotvec0_single_active_bit_constraint.c0);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, hotvec0_single_active_bit_constraint.c1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, hotvec0_single_active_bit_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, hotvec0_single_active_bit_constraint.c1);
	#elif (FAEST_RING_HOTVECTOR_DIM == 2)
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, hotvec0_single_active_bit_constraint.c0);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, hotvec0_single_active_bit_constraint.c1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, hotvec0_single_active_bit_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, hotvec0_single_active_bit_constraint.c1);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad, hotvec1_single_active_bit_constraint.c0);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic, hotvec1_single_active_bit_constraint.c1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, hotvec1_single_active_bit_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, hotvec1_single_active_bit_constraint.c1);
	#elif (FAEST_RING_HOTVECTOR_DIM == 4)
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad,  poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic,  poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quartic, hotvec0_single_active_bit_constraint.c0);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quintic, hotvec0_single_active_bit_constraint.c1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quartic, hotvec0_single_active_bit_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quintic, hotvec0_single_active_bit_constraint.c1);

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad,  poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic,  poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quartic, hotvec1_single_active_bit_constraint.c0);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quintic, hotvec1_single_active_bit_constraint.c1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quartic, hotvec1_single_active_bit_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quintic, hotvec1_single_active_bit_constraint.c1);

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad,  poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic,  poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quartic, hotvec2_single_active_bit_constraint.c0);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quintic, hotvec2_single_active_bit_constraint.c1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quartic, hotvec2_single_active_bit_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quintic, hotvec2_single_active_bit_constraint.c1);

	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quad,  poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_cubic,  poly_secpar_from_byte(0));
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quartic, hotvec3_single_active_bit_constraint.c0);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_quintic, hotvec3_single_active_bit_constraint.c1);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_linear, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quad, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_cubic, poly_secpar_from_byte(0));
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quartic, hotvec3_single_active_bit_constraint.c0);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_quintic, hotvec3_single_active_bit_constraint.c1);
	#endif

	// JC: Final ZKHash.
	// quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
	// quicksilver_final(state, &state->state_secpar_linear, &state->state_64_linear, value_mask, proof_lin);
	// quicksilver_final(state, &state->state_secpar_quad, &state->state_64_quad, zero_mask, proof_quad);
	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mask_c0, check);
	quicksilver_final(state, &state->state_secpar_linear, &state->state_64_linear, mask_c1, proof_lin);
	quicksilver_final(state, &state->state_secpar_quad, &state->state_64_quad, mask_c2, proof_quad);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	quicksilver_final(state, &state->state_secpar_cubic, &state->state_64_cubic, mask_c3, proof_cubic);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	quicksilver_final(state, &state->state_secpar_quartic, &state->state_64_quartic, mask_c4, proof_quartic);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	quicksilver_final(state, &state->state_secpar_quintic, &state->state_64_quintic, mask_c5, proof_quintic);
	#endif
}

#if (FAEST_RING_HOTVECTOR_DIM == 1)
void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin, uint8_t* restrict check)
#elif  (FAEST_RING_HOTVECTOR_DIM == 2)
void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits, const uint8_t* restrict proof_cubic,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin, uint8_t* restrict check)
#elif  (FAEST_RING_HOTVECTOR_DIM == 4)
void quicksilver_verify_or(quicksilver_state* state, size_t witness_bits, const uint8_t* restrict proof_quintic,
						   const uint8_t* restrict proof_quartic, const uint8_t* restrict proof_cubic,
                           const uint8_t* restrict proof_quad, const uint8_t* restrict proof_lin, uint8_t* restrict check)
#endif
{
	assert(state->verifier);

	qs_verifier_key* hotvec0;
	size_t vec_size = (FAEST_RING_HOTVECTOR_BITS+1) * sizeof(qs_verifier_key);
    hotvec0 = (qs_verifier_key *)aligned_alloc(alignof(qs_verifier_key), vec_size);
	assert(hotvec0 != NULL);
	qs_verifier_key hotvec0_sum;
	quicksilver_verifier_init_key_0(state, &hotvec0_sum);
	qs_verifier_key hotvec0_mul_idx_sum;
	quicksilver_verifier_init_key_0(state, &hotvec0_mul_idx_sum);

	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	qs_verifier_key* hotvec1;
    hotvec1 = (qs_verifier_key *)aligned_alloc(alignof(qs_verifier_key), vec_size);
	assert(hotvec1 != NULL);
	qs_verifier_key hotvec1_sum;
	quicksilver_verifier_init_key_0(state, &hotvec1_sum);
	qs_verifier_key hotvec1_mul_idx_sum;
	quicksilver_verifier_init_key_0(state, &hotvec1_mul_idx_sum);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	qs_verifier_key* hotvec2;
    hotvec2 = (qs_verifier_key *)aligned_alloc(alignof(qs_verifier_key), vec_size);
	assert(hotvec2!= NULL);
	qs_verifier_key hotvec2_sum;
	quicksilver_verifier_init_key_0(state, &hotvec2_sum);
	qs_verifier_key hotvec2_mul_idx_sum;
	quicksilver_verifier_init_key_0(state, &hotvec2_mul_idx_sum);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	qs_verifier_key* hotvec3;
    hotvec3 = (qs_verifier_key *)aligned_alloc(alignof(qs_verifier_key), vec_size);
	assert(hotvec3 != NULL);
	qs_verifier_key hotvec3_sum;
	quicksilver_verifier_init_key_0(state, &hotvec3_sum);
	qs_verifier_key hotvec3_mul_idx_sum;
	quicksilver_verifier_init_key_0(state, &hotvec3_mul_idx_sum);
	#endif

	for (uint32_t idx = 0; idx <FAEST_RING_HOTVECTOR_BITS+1; idx++) {
		if (idx < FAEST_RING_HOTVECTOR_BITS){
			hotvec0[idx].key = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx]);
			hotvec0[idx].deg = 1;
			#if (FAEST_RING_HOTVECTOR_DIM > 1)
			hotvec1[idx].key = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx + FAEST_RING_HOTVECTOR_BITS]);
			hotvec1[idx].deg = 1;
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 2)
			hotvec2[idx].key = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx + 2*FAEST_RING_HOTVECTOR_BITS]);
			hotvec2[idx].deg = 1;
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 3)
			hotvec3[idx].key = poly_secpar_load_dup(&state->macs[witness_bits - FAEST_RING_HOTVECTOR_BYTES * 8 + idx + 3*FAEST_RING_HOTVECTOR_BITS]);
			hotvec3[idx].deg = 1;
			#endif
		}
		else {
			hotvec0[idx] = quicksilver_verifier_const_add_key(state, poly_secpar_from_byte(1), hotvec0_sum);
			#if (FAEST_RING_HOTVECTOR_DIM > 1)
			hotvec1[idx] = quicksilver_verifier_const_add_key(state, poly_secpar_from_byte(1), hotvec1_sum);
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 2)
			hotvec2[idx] = quicksilver_verifier_const_add_key(state, poly_secpar_from_byte(1), hotvec2_sum);
			#endif
			#if (FAEST_RING_HOTVECTOR_DIM > 3)
			hotvec3[idx] = quicksilver_verifier_const_add_key(state, poly_secpar_from_byte(1), hotvec3_sum);
			#endif
		}
		hotvec0_sum = quicksilver_verifier_key_add_key(state, hotvec0_sum, hotvec0[idx]);
		qs_verifier_key tmp	= quicksilver_verifier_const_mul_key(state, poly_secpar_from_1(idx + 1), hotvec0[idx]);
		hotvec0_mul_idx_sum = quicksilver_verifier_key_add_key(state, hotvec0_mul_idx_sum, tmp);

		#if (FAEST_RING_HOTVECTOR_DIM > 1)
		hotvec1_sum = quicksilver_verifier_key_add_key(state, hotvec1_sum, hotvec1[idx]);
		qs_verifier_key tmp1 = quicksilver_verifier_const_mul_key(state, poly_secpar_from_1(idx + 1), hotvec1[idx]);
		hotvec1_mul_idx_sum = quicksilver_verifier_key_add_key(state, hotvec1_mul_idx_sum, tmp1);
		#endif
		#if (FAEST_RING_HOTVECTOR_DIM > 2)
		hotvec2_sum = quicksilver_verifier_key_add_key(state, hotvec2_sum, hotvec2[idx]);
		qs_verifier_key tmp2 = quicksilver_verifier_const_mul_key(state, poly_secpar_from_1(idx + 1), hotvec2[idx]);
		hotvec2_mul_idx_sum = quicksilver_verifier_key_add_key(state, hotvec2_mul_idx_sum, tmp2);
		#endif
		#if (FAEST_RING_HOTVECTOR_DIM > 3)
		hotvec3_sum = quicksilver_verifier_key_add_key(state, hotvec3_sum, hotvec3[idx]);
		qs_verifier_key tmp3 = quicksilver_verifier_const_mul_key(state, poly_secpar_from_1(idx + 1), hotvec3[idx]);
		hotvec3_mul_idx_sum = quicksilver_verifier_key_add_key(state, hotvec3_mul_idx_sum, tmp3);
		#endif
	}

	for (uint32_t branch = 0; branch <FAEST_RING_SIZE; branch++) {

		qs_verifier_key branch_constraint;
		branch_constraint.key = quicksilver_lincombine_hasher_state(state, &state->state_or_secpar_const[branch], &state->state_or_64_const[branch]);
		branch_constraint.deg = 2;

		// JC: Decompose branch idx into (i,j).
		uint32_t base = FAEST_RING_HOTVECTOR_BITS + 1;
		uint32_t decomp[FAEST_RING_HOTVECTOR_DIM] = {0};
		base_decompose(branch, base, decomp, FAEST_RING_HOTVECTOR_DIM);

		#if (FAEST_RING_HOTVECTOR_DIM == 1)
		qs_verifier_key final_branch_constraint = quicksilver_verifier_key_mul_key(state, hotvec0[decomp[0]], branch_constraint);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, final_branch_constraint.key);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, final_branch_constraint.key);
		#elif (FAEST_RING_HOTVECTOR_DIM == 2)
		qs_verifier_key selector_tmp = quicksilver_verifier_key_mul_key(state, hotvec0[decomp[0]], hotvec1[decomp[1]]);
		qs_verifier_key final_branch_constraint = quicksilver_verifier_key_mul_key(state, selector_tmp, branch_constraint);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, final_branch_constraint.key);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, final_branch_constraint.key);
		#elif (FAEST_RING_HOTVECTOR_DIM == 4)
		qs_verifier_key selector_tmp0 = quicksilver_verifier_key_mul_key(state, hotvec0[decomp[0]], hotvec1[decomp[1]]);
		qs_verifier_key selector_tmp1 = quicksilver_verifier_key_mul_key(state, hotvec2[decomp[2]], hotvec3[decomp[3]]);
		qs_verifier_key selector = quicksilver_verifier_key_mul_key(state, selector_tmp0, selector_tmp1);
		qs_verifier_key final_branch_constraint = quicksilver_verifier_key_mul_key(state, selector, branch_constraint);
		hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, final_branch_constraint.key);
		hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, final_branch_constraint.key);
		#endif
	}

	// JC: Well-formedness of hotvec (single active bit).
	qs_verifier_key hotvec0_const2;
	quicksilver_verifier_init_key_0(state, &hotvec0_const2);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	qs_verifier_key hotvec1_const2;
	quicksilver_verifier_init_key_0(state, &hotvec1_const2);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	qs_verifier_key hotvec2_const2;
	quicksilver_verifier_init_key_0(state, &hotvec2_const2);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	qs_verifier_key hotvec3_const2;
	quicksilver_verifier_init_key_0(state, &hotvec3_const2);
	#endif

	for (uint32_t idx = 0; idx <FAEST_RING_HOTVECTOR_BITS+1; idx++) {
		qs_verifier_key tmp = quicksilver_verifier_const_add_key(state, poly_secpar_from_1(idx + 1), hotvec0_mul_idx_sum);
		tmp = quicksilver_verifier_key_mul_key(state, tmp, hotvec0[idx]);
		hotvec0_const2 = quicksilver_verifier_key_add_key(state, hotvec0_const2, tmp);
		#if (FAEST_RING_HOTVECTOR_DIM > 1)
		qs_verifier_key tmp1 = quicksilver_verifier_const_add_key(state, poly_secpar_from_1(idx + 1), hotvec1_mul_idx_sum);
		tmp1 = quicksilver_verifier_key_mul_key(state, tmp1, hotvec1[idx]);
		hotvec1_const2 = quicksilver_verifier_key_add_key(state, hotvec1_const2, tmp1);
		#endif
		#if (FAEST_RING_HOTVECTOR_DIM > 2)
		qs_verifier_key tmp2 = quicksilver_verifier_const_add_key(state, poly_secpar_from_1(idx + 1), hotvec2_mul_idx_sum);
		tmp2 = quicksilver_verifier_key_mul_key(state, tmp2, hotvec2[idx]);
		hotvec2_const2 = quicksilver_verifier_key_add_key(state, hotvec2_const2, tmp2);
		#endif
		#if (FAEST_RING_HOTVECTOR_DIM > 3)
		qs_verifier_key tmp3 = quicksilver_verifier_const_add_key(state, poly_secpar_from_1(idx + 1), hotvec3_mul_idx_sum);
		tmp3 = quicksilver_verifier_key_mul_key(state, tmp3, hotvec3[idx]);
		hotvec3_const2 = quicksilver_verifier_key_add_key(state, hotvec3_const2, tmp3);
		#endif
	}

	free(hotvec0);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	free(hotvec1);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	free(hotvec2);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	free(hotvec3);
	#endif

	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	quicksilver_verifier_increase_key_deg(state, &hotvec0_const2, 1);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec0_const2.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec0_const2.key);
	#elif (FAEST_RING_HOTVECTOR_DIM == 2)
	quicksilver_verifier_increase_key_deg(state, &hotvec0_const2, 2);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec0_const2.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec0_const2.key);
	quicksilver_verifier_increase_key_deg(state, &hotvec1_const2, 2);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec1_const2.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec1_const2.key);
	#elif (FAEST_RING_HOTVECTOR_DIM == 4)
	quicksilver_verifier_increase_key_deg(state, &hotvec0_const2, 4);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec0_const2.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec0_const2.key);
	quicksilver_verifier_increase_key_deg(state, &hotvec1_const2, 4);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec1_const2.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec1_const2.key);
	quicksilver_verifier_increase_key_deg(state, &hotvec2_const2, 4);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec2_const2.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec2_const2.key);
	quicksilver_verifier_increase_key_deg(state, &hotvec3_const2, 4);
	hasher_gfsecpar_update(&state->key_secpar, &state->state_secpar_const, hotvec3_const2.key);
	hasher_gfsecpar_64_update(&state->key_64, &state->state_64_const, hotvec3_const2.key);
	#endif

	poly_secpar_vec linear_term = poly_secpar_load_dup(proof_lin);
	poly_secpar_vec quad_term = poly_secpar_load_dup(proof_quad);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	poly_secpar_vec cubic_term = poly_secpar_load_dup(proof_cubic);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	poly_secpar_vec quartic_term = poly_secpar_load_dup(proof_quartic);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	poly_secpar_vec quintic_term = poly_secpar_load_dup(proof_quintic);
	#endif

	qs_verifier_key mask1;
	qs_verifier_key mask2;
	quicksilver_verifier_init_key_0(state, &mask1);
	quicksilver_verifier_init_key_0(state, &mask2);
	mask1.key = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits));
	mask2.key = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits + SECURITY_PARAM));
	quicksilver_verifier_increase_key_deg(state, &mask2, 1);
	qs_verifier_key qs_mask = quicksilver_verifier_key_add_key(state, mask1, mask2);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	qs_verifier_key mask3;
	quicksilver_verifier_init_key_0(state, &mask3);
	mask3.key = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits + 2*SECURITY_PARAM));
	quicksilver_verifier_increase_key_deg(state, &mask3, 2);
	qs_mask = quicksilver_verifier_key_add_key(state, qs_mask, mask3);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	qs_verifier_key mask4;
	quicksilver_verifier_init_key_0(state, &mask4);
	mask4.key = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits + 3*SECURITY_PARAM));
	quicksilver_verifier_increase_key_deg(state, &mask4, 3);
	qs_mask = quicksilver_verifier_key_add_key(state, qs_mask, mask4);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	qs_verifier_key mask5;
	quicksilver_verifier_init_key_0(state, &mask5);
	mask5.key = poly_2secpar_reduce_secpar(combine_mask_macs(state, witness_bits + 4*SECURITY_PARAM));
	quicksilver_verifier_increase_key_deg(state, &mask5, 4);
	qs_mask = quicksilver_verifier_key_add_key(state, qs_mask, mask5);
	#endif

	// poly_2secpar_vec mac_mask = combine_mask_macs(state, witness_bits);

	poly_2secpar_vec mac_mask = poly_2secpar_from_secpar(qs_mask.key);
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(linear_term, state->delta));
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(quad_term, state->deltaSq));

	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	poly_secpar_vec delta_cubic = poly_2secpar_reduce_secpar(poly_secpar_mul(state->delta, state->deltaSq));
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(cubic_term,delta_cubic));
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	poly_secpar_vec delta_quartic = poly_2secpar_reduce_secpar(poly_secpar_mul(state->deltaSq, state->deltaSq));
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(quartic_term, delta_quartic));
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	poly_secpar_vec delta_quintic = poly_2secpar_reduce_secpar(poly_secpar_mul(delta_quartic, state->delta));
	mac_mask = poly_2secpar_add(mac_mask, poly_secpar_mul(quintic_term, delta_quintic));
	#endif
	quicksilver_final(state, &state->state_secpar_const, &state->state_64_const, mac_mask, check);
}

extern inline quicksilver_vec_gf2 quicksilver_get_witness_vec(const quicksilver_state* state, size_t index);
extern inline poly_secpar_vec quicksilver_get_delta(const quicksilver_state* state);
extern inline quicksilver_vec_gf2 quicksilver_add_gf2(const quicksilver_state* state, quicksilver_vec_gf2 x, quicksilver_vec_gf2 y);
extern inline quicksilver_vec_gfsecpar quicksilver_add_gfsecpar(const quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y);
extern inline quicksilver_vec_deg2 quicksilver_add_deg2(const quicksilver_state* state, quicksilver_vec_deg2 x, quicksilver_vec_deg2 y);
extern inline quicksilver_vec_deg2 quicksilver_add_deg2_deg1(const quicksilver_state* state, quicksilver_vec_deg2 x, quicksilver_vec_gfsecpar y);
extern inline quicksilver_vec_gf2 quicksilver_zero_gf2();
extern inline quicksilver_vec_gfsecpar quicksilver_zero_gfsecpar();
extern inline quicksilver_vec_deg2 quicksilver_zero_deg2();
extern inline quicksilver_vec_gf2 quicksilver_one_gf2(const quicksilver_state* state);
extern inline quicksilver_vec_gfsecpar quicksilver_one_gfsecpar(const quicksilver_state* state);
extern inline quicksilver_vec_deg2 quicksilver_one_deg2(const quicksilver_state* state);
extern inline quicksilver_vec_gf2 quicksilver_const_gf2(const quicksilver_state* state, poly1_vec c);
extern inline quicksilver_vec_gfsecpar quicksilver_const_gfsecpar(const quicksilver_state* state, poly_secpar_vec c);
extern inline quicksilver_vec_deg2 quicksilver_const_deg2(const quicksilver_state* state, poly_secpar_vec c);
extern inline quicksilver_vec_deg2 quicksilver_const_deg2_gf2(const quicksilver_state* state, poly1_vec c);
extern inline quicksilver_vec_gf2 quicksilver_mul_const_gf2(const quicksilver_state* state, quicksilver_vec_gf2 x, poly1_vec c);
extern inline quicksilver_vec_gfsecpar quicksilver_mul_const(const quicksilver_state* state, quicksilver_vec_gfsecpar x, poly_secpar_vec c);
extern inline void quicksilver_mul_by_two(const quicksilver_state* state, const quicksilver_vec_gf2* x_bits, quicksilver_vec_gf2* res);
extern inline quicksilver_vec_deg2 quicksilver_mul_const_deg2_gf2(const quicksilver_state* state, quicksilver_vec_deg2 x, poly1_vec c);
extern inline quicksilver_vec_deg2 quicksilver_mul_const_deg2(const quicksilver_state* state, quicksilver_vec_deg2 x, poly_secpar_vec c);
extern inline quicksilver_vec_deg2 quicksilver_mul(const quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y);
extern inline quicksilver_vec_gfsecpar quicksilver_combine_1_bit(const quicksilver_state* state, const quicksilver_vec_gf2 qs_bit);
extern inline quicksilver_vec_gfsecpar quicksilver_combine_8_bits(const quicksilver_state* state, const quicksilver_vec_gf2* qs_bits);
extern inline quicksilver_vec_gfsecpar quicksilver_combine_16_bits(const quicksilver_state* state, const quicksilver_vec_gf2* qs_bits);
extern inline quicksilver_vec_gfsecpar quicksilver_combine_secpar_bits(const quicksilver_state* state, const quicksilver_vec_gf2* qs_bits);
extern inline quicksilver_vec_gfsecpar quicksilver_const_8_bits(const quicksilver_state* state, const void* s);
extern inline quicksilver_vec_gfsecpar quicksilver_const_secpar_bits(const quicksilver_state* state, const void* s);
extern inline quicksilver_vec_gfsecpar quicksilver_get_witness_8_bits(const quicksilver_state* state, size_t bit_index);
extern inline quicksilver_vec_gfsecpar quicksilver_sq_bits(const quicksilver_state* state, const quicksilver_vec_gf2* x_bits);
extern inline void quicksilver_constraint(quicksilver_state* state, quicksilver_vec_deg2 x, bool ring);
extern inline void quicksilver_inverse_constraint(quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y, bool ring);
extern inline void quicksilver_pseudoinverse_constraint(quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y, quicksilver_vec_gfsecpar x_sq, quicksilver_vec_gfsecpar y_sq, bool ring);
extern inline void quicksilver_constraint_to_branch(quicksilver_state* state, uint32_t branch, quicksilver_vec_deg2 x);
extern inline void quicksilver_inverse_constraint_to_branch(quicksilver_state* state, uint32_t branch, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y);
extern inline void quicksilver_pseudoinverse_constraint_to_branch(quicksilver_state* state, uint32_t branch, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y, quicksilver_vec_gfsecpar x_sq, quicksilver_vec_gfsecpar y_sq);
extern inline void quicksilver_pseudoinverse_constraint_to_branch_and_cache(quicksilver_state* state, uint32_t branch, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y, quicksilver_vec_gfsecpar x_sq, quicksilver_vec_gfsecpar y_sq, quicksilver_vec_deg2* constraint1_cached, quicksilver_vec_deg2* constraint2_cached);
extern inline void quicksilver_prover_init_poly_deg1(const quicksilver_state* state, qs_prover_poly_deg1* in);
extern inline void quicksilver_prover_init_poly_deg2(const quicksilver_state* state, qs_prover_poly_deg2* in);
extern inline void quicksilver_prover_init_poly_deg3(const quicksilver_state* state, qs_prover_poly_deg3* in);
extern inline void quicksilver_prover_init_poly_deg4(const quicksilver_state* state, qs_prover_poly_deg4* in);
extern inline void quicksilver_prover_init_poly_deg5(const quicksilver_state* state, qs_prover_poly_deg5* in);
extern inline void quicksilver_verifier_init_key_0(const quicksilver_state* state, qs_verifier_key* in);
extern inline qs_prover_poly_deg1 qs_prover_poly_deg1_add_deg1(const quicksilver_state* state, const qs_prover_poly_deg1 left, const qs_prover_poly_deg1 right);
extern inline qs_prover_poly_deg2 qs_prover_poly_deg1_add_deg2(const quicksilver_state* state, const qs_prover_poly_deg1 left, const qs_prover_poly_deg2 right);
extern inline qs_prover_poly_deg3 qs_prover_poly_deg2_add_deg3(const quicksilver_state* state, const qs_prover_poly_deg2 left, const qs_prover_poly_deg3 right);
extern inline qs_prover_poly_deg4 qs_prover_poly_deg3_add_deg4(const quicksilver_state* state, const qs_prover_poly_deg3 left, const qs_prover_poly_deg4 right);
extern inline qs_prover_poly_deg5 qs_prover_poly_deg4_add_deg5(const quicksilver_state* state, const qs_prover_poly_deg4 left, const qs_prover_poly_deg5 right);
extern inline qs_prover_poly_deg1 qs_prover_poly_const_add_deg1(const quicksilver_state* state, const poly_secpar_vec left, const qs_prover_poly_deg1 right);
extern inline qs_prover_poly_deg2 qs_prover_poly_deg2_add_deg2(const quicksilver_state* state, const qs_prover_poly_deg2 left, const qs_prover_poly_deg2 right);
extern inline qs_prover_poly_deg1 qs_prover_poly_const_mul_deg1(const quicksilver_state* state, const poly_secpar_vec left, const qs_prover_poly_deg1 right);
extern inline qs_prover_poly_deg2 qs_prover_poly_deg1_mul_deg1(const quicksilver_state* state, const qs_prover_poly_deg1 left, const qs_prover_poly_deg1 right);
extern inline qs_prover_poly_deg3 qs_prover_poly_deg1_mul_deg2(const quicksilver_state* state, const qs_prover_poly_deg1 left, const qs_prover_poly_deg2 right);
extern inline qs_prover_poly_deg4 qs_prover_poly_deg2_mul_deg2(const quicksilver_state* state, const qs_prover_poly_deg2 left, const qs_prover_poly_deg2 right);
extern inline qs_prover_poly_deg6 qs_prover_poly_deg2_mul_deg4(const quicksilver_state* state, const qs_prover_poly_deg2 left, const qs_prover_poly_deg4 right);
extern inline qs_verifier_key quicksilver_verifier_const_add_key(const quicksilver_state* state, const poly_secpar_vec left, const qs_verifier_key right);
extern inline qs_verifier_key quicksilver_verifier_const_mul_key(const quicksilver_state* state, const poly_secpar_vec left, const qs_verifier_key right);
extern inline qs_verifier_key quicksilver_verifier_key_add_key(const quicksilver_state* state, const qs_verifier_key left, const qs_verifier_key right);
extern inline qs_verifier_key quicksilver_verifier_key_mul_key(const quicksilver_state* state, const qs_verifier_key left, const qs_verifier_key right);
extern inline void quicksilver_verifier_increase_key_deg(const quicksilver_state* state, qs_verifier_key* in, size_t deg);

