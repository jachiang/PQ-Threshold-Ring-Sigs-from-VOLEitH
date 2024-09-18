#include "faest.h"
#include "faest_details.h"

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hash.h"
#include "owf_proof.h"
#include "small_vole.h"
#include "vole_commit.h"
#include "util.h"

void faest_free_public_key(public_key* pk)
{
#if defined(OWF_MQ_2_1) || defined(OWF_MQ_2_8)
	free(pk->mq_A_b);
	pk->mq_A_b = NULL;
#else
	(void) pk;
#endif
}

void faest_free_secret_key(secret_key* sk)
{
	faest_free_public_key(&sk->pk);
}

// done
bool faest_unpack_secret_key(secret_key* unpacked, const uint8_t* packed, bool ring)
{
	memcpy(&unpacked->pk.owf_input, packed, sizeof(unpacked->pk.owf_input));				// for MQ, here goes the seed
	memcpy(&unpacked->sk, packed + sizeof(unpacked->pk.owf_input), sizeof(unpacked->sk));	// for MQ, here goes the x

#if defined(OWF_AES_CTR)
	aes_keygen(&unpacked->round_keys, unpacked->sk);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked->pk.fixed_key, unpacked->pk.owf_input[0]);
#elif defined(OWF_RAIN_3) || defined(OWF_RAIN_4)
	// I do not think, here anything needs to be done for Rain. We can directly call the faest_compute_witness as rain uses the sk for everyround
		// and does not have rk
#elif defined(OWF_MQ_2_1) || defined(OWF_MQ_2_8)
	unpacked->pk.mq_A_b = aligned_alloc(alignof(block_secpar), MQ_A_B_LENGTH * sizeof(block_secpar));
	mq_initialize(unpacked->sk, unpacked->pk.owf_input[0], unpacked->pk.mq_A_b, unpacked->pk.mq_y_gfsecpar, unpacked->pk.owf_output);
#endif

	if (!faest_compute_witness(unpacked, ring)) // TODO: handle tagged ring flag.
	{
		faest_free_secret_key(unpacked);
		return false;
	}

	return true;
}

// nothing to do here i guess
void faest_pack_public_key(uint8_t* packed, const public_key* unpacked)
{
	memcpy(packed, &unpacked->owf_input, sizeof(unpacked->owf_input));
	memcpy(packed + sizeof(unpacked->owf_input), &unpacked->owf_output[0], sizeof(unpacked->owf_output));
}


void faest_unpack_public_key(public_key* unpacked, const uint8_t* packed)
{
	memcpy(&unpacked->owf_input, packed, sizeof(unpacked->owf_input));
	memcpy(&unpacked->owf_output[0], packed + sizeof(unpacked->owf_input), sizeof(unpacked->owf_output));
#if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked->fixed_key, unpacked->owf_input[0]);
#elif defined(OWF_MQ_2_1) || defined(OWF_MQ_2_8)
	unpacked->mq_A_b = aligned_alloc(alignof(block_secpar), MQ_A_B_LENGTH * sizeof(block_secpar));
	mq_initialize_pk(unpacked->owf_input[0], unpacked->owf_output, unpacked->mq_A_b, unpacked->mq_y_gfsecpar);
#endif
}

// done
bool faest_compute_witness(secret_key* sk, bool ring)
{
	uint8_t* w_ptr;
	if (!ring) {
		w_ptr = (uint8_t*) &sk->witness;
	}
	else if (ring) {
		w_ptr = (uint8_t*) &sk->ring_witness;
	}

#if defined(OWF_MQ_2_1) || defined(OWF_MQ_2_8)

	// Setting key
	memcpy(w_ptr, sk->sk, MQ_N_BYTES);
	w_ptr += (MQ_M*MQ_GF_BITS)/8;

	return true;
#else
	memcpy(w_ptr, &sk->sk, sizeof(sk->sk));
	w_ptr += sizeof(sk->sk);

#if defined(OWF_AES_CTR)
	// Extract witness for key schedule.
	for (size_t i = SECURITY_PARAM / 8; i < OWF_BLOCK_SIZE * (OWF_ROUNDS + 1);
	     i += OWF_KEY_SCHEDULE_PERIOD, w_ptr += 4)
	{
		uint32_t prev_word, word;
		memcpy(&prev_word, ((uint8_t*) &sk->round_keys.keys[0]) + i - SECURITY_PARAM / 8, 4);
		memcpy(&word, ((uint8_t*) &sk->round_keys.keys[0]) + i, 4);
		memcpy(w_ptr, &word, 4);

		uint32_t sbox_output = word ^ prev_word;
		if (SECURITY_PARAM != 256 || i % (SECURITY_PARAM / 8) == 0)
			sbox_output ^= aes_round_constants[i / (SECURITY_PARAM / 8) - 1];

		// https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
		sbox_output ^= 0x63636363; // AES SBox maps 0 to 0x63.
		if ((sbox_output - 0x01010101) & ~sbox_output & 0x80808080)
			return false;
	}
#endif

#if defined(OWF_AES_CTR)
	for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
		sk->pk.owf_output[i] =
			owf_block_xor(sk->round_keys.keys[0], sk->pk.owf_input[i]);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	static_assert(OWF_BLOCKS == 1, "");
	sk->pk.owf_output[0] = owf_block_xor(sk->pk.fixed_key.keys[0], sk->sk);
#elif defined(OWF_RAIN_3)	// This should be similar to EM, except I will add the sk later in the round function call
	static_assert(OWF_BLOCKS == 1, "");
	sk->pk.owf_output[0] = sk->pk.owf_input[0];
#elif defined(OWF_RAIN_4)	// This should be similar to EM, except I will add the sk later in the round function call
	static_assert(OWF_BLOCKS == 1, "");
	sk->pk.owf_output[0] = sk->pk.owf_input[0];
#endif

	for (unsigned int round = 1; round <= OWF_ROUNDS; ++round)
	{
		for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
		{
			#if !defined(ALLOW_ZERO_SBOX) && (defined(OWF_AES_CTR) || defined(OWF_RIJNDAEL_EVEN_MANSOUR))
			// The block is about to go into the SBox, so check for zeros.
			if (owf_block_any_zeros(sk->pk.owf_output[i]))
				return false;
			#endif

			owf_block after_sbox;
#if defined(OWF_AES_CTR)
			aes_round_function(&sk->round_keys, &sk->pk.owf_output[i], &after_sbox, round);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	#if SECURITY_PARAM == 128
			aes_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
	#elif SECURITY_PARAM == 192
			rijndael192_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
	#elif SECURITY_PARAM == 256
			rijndael256_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
	#endif
#elif defined(OWF_RAIN_3)
	#if SECURITY_PARAM == 128
			if (round != OWF_ROUNDS) {
				rain_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_128[round-1],rain_mat_128[(round-1)*128],(uint64_t*)&after_sbox);
			} else {
				rain_last_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_128[round-1]);
			}
	#elif SECURITY_PARAM == 192
			if (round != OWF_ROUNDS) {
				rain_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_192[round-1],rain_mat_192[(round-1)*192],(uint64_t*)&after_sbox);
			} else {
				rain_last_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_192[round-1]);
			}
	#elif SECURITY_PARAM == 256
			if (round != OWF_ROUNDS) {
				rain_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_256[round-1],rain_mat_256[(round-1)*256],(uint64_t*)&after_sbox);
			} else {
				rain_last_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_256[round-1]);
			}

	#endif
#elif defined(OWF_RAIN_4)
	#if SECURITY_PARAM == 128
		if (round != OWF_ROUNDS) {
			rain_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_128[round-1],rain_mat_128[(round-1)*128],(uint64_t*)&after_sbox);
		} else {
			rain_last_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_128[round-1]);
		}
	#elif SECURITY_PARAM == 192
		if (round != OWF_ROUNDS) {
			rain_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_192[round-1],rain_mat_192[(round-1)*192],(uint64_t*)&after_sbox);
		} else {
			rain_last_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_192[round-1]);
		}
	#elif SECURITY_PARAM == 256
		if (round != OWF_ROUNDS) {
			rain_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_256[round-1],rain_mat_256[(round-1)*256],(uint64_t*)&after_sbox);
		} else {
			rain_last_round_function((uint64_t*)&sk->pk.owf_output[i],(uint64_t*)&sk->sk,rain_rc_256[round-1]);
		}
	#endif
#endif

			if (round < OWF_ROUNDS)
				memcpy(w_ptr + i * sizeof(owf_block) * (OWF_ROUNDS - 1), &after_sbox, sizeof(owf_block));
		}

		if (round < OWF_ROUNDS)
			w_ptr += sizeof(owf_block);
	}

	w_ptr += (OWF_BLOCKS - 1) * sizeof(owf_block) * (OWF_ROUNDS - 1);

#if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
		sk->pk.owf_output[i] = owf_block_xor(sk->pk.owf_output[i], sk->sk);
#endif

#endif

	if(!ring) {
		assert(w_ptr - (uint8_t*) &sk->witness == WITNESS_BITS / 8);
		memset(w_ptr, 0, sizeof(sk->witness) - WITNESS_BITS / 8);
	}
	else {
		// JC: Decompose active branch index (according to hotvector size/dim).
		uint32_t base = FAEST_RING_HOTVECTOR_BITS + 1;
		uint32_t decomp[FAEST_RING_HOTVECTOR_DIM] = {0};
		base_decompose(sk->idx, base, decomp, FAEST_RING_HOTVECTOR_DIM);

		// JC: Serialization of hotvectors as bytes.
		uint8_t hotvectors_bytes[(FAEST_RING_HOTVECTOR_BITS * FAEST_RING_HOTVECTOR_DIM + 7) / 8] = {0};

		// JC: Init indices and vars.
		int curr_byte_idx = 0;
		int curr_bit_idx = 0;

		for (int i = 0; i < FAEST_RING_HOTVECTOR_DIM; ++i) {
			// JC: Remaining free bits in current byte.
			int remaining_bits = 8 - curr_bit_idx;
			if ((decomp[i] != base - 1)) {
				// JC: Hotvector has exactly one active bit.
				uint32_t hotvector_idx = decomp[i];
				int active_bit_idx = (curr_bit_idx + hotvector_idx) % 8;
				int active_byte_idx = curr_byte_idx;
				if (hotvector_idx + 1 > remaining_bits) {
					active_byte_idx = ((hotvector_idx - remaining_bits + 7 + 1) / 8) + curr_byte_idx;
				}
				// printf("Active byte idx: %u \n", active_byte_idx);
				// printf("Active bit idx: %u \n", active_bit_idx);

				// JC: Activate bit in hotvectors byte array.
				hotvectors_bytes[active_byte_idx] = hotvectors_bytes[active_byte_idx] ^ (1 << (active_bit_idx));
			}
			// else{
			// 	if (decomp[i] == base - 1) {
			// 		printf("Last active bit omitted in hotvector %u\n", i);
			// 	}
			// }
			// // JC: Update indices vars.
			curr_byte_idx = (FAEST_RING_HOTVECTOR_BITS - remaining_bits + 7) / 8 + curr_byte_idx;
			curr_bit_idx = (curr_bit_idx + FAEST_RING_HOTVECTOR_BITS) % 8;
		}

		// JC: Copy hotvector serialization to witness.
		memcpy(w_ptr, hotvectors_bytes, (FAEST_RING_HOTVECTOR_BITS * FAEST_RING_HOTVECTOR_DIM + 7) / 8);
	}
	return true;
}

// done
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed, secret_key* sk)
{
	if (!faest_unpack_secret_key(sk, sk_packed, false)) // JC: Unpacks sk with witness for non-ring sig.
		return false;

	faest_pack_public_key(pk_packed, &sk->pk);
	return true;
}
// done
bool faest_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed)
{
	secret_key sk;
	if (!faest_unpack_sk_and_get_pubkey(pk_packed, sk_packed, &sk))
		return false;

	faest_free_secret_key(&sk);
	return true;
}

static bool faest_sign_attempt(
	uint8_t* signature, const uint8_t* msg, size_t msg_len,
	const secret_key* sk, const uint8_t* pk_packed,
	const uint8_t* random_seed, size_t random_seed_len, uint64_t attempt_num)
{
	// TODO: Do we need to domain separate by the faest parameters?

	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_packed, FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, msg, msg_len);
	hash_update_byte(&hasher, 1);
	hash_final(&hasher, &mu, sizeof(mu));

	block_secpar seed;
	block128 iv;
	uint8_t seed_iv[sizeof(seed) + sizeof(iv)];

	hash_init(&hasher);
	hash_update(&hasher, &sk->sk, sizeof(sk->sk));
	hash_update(&hasher, &mu, sizeof(mu));
	if (random_seed)
		hash_update(&hasher, random_seed, random_seed_len);

	// Always succeed first try if COUNTER_BYTES == 0, so don't bother hashing attempt_num == 0.
#if COUNTER_BYTES > 0
	uint8_t attempt_num_bytes[8];
	#ifdef __GNUC__
	#pragma GCC unroll (8)
	#endif
	for (int i = 0; i < 8; ++i)
		attempt_num_bytes[i] = attempt_num >> (8*i);
	hash_update(&hasher, &attempt_num_bytes[0], sizeof(attempt_num_bytes));
#else
	// suppress unused argument warning
	(void) attempt_num;
#endif

	hash_update_byte(&hasher, 3);
	hash_final(&hasher, seed_iv, sizeof(seed_iv));

	memcpy(&seed, seed_iv, sizeof(seed));
	memcpy(&iv, &seed_iv[sizeof(seed)], sizeof(iv));

	block_secpar* forest =
		aligned_alloc(alignof(block_secpar), FOREST_SIZE * sizeof(block_secpar));
	block_2secpar* hashed_leaves =
		aligned_alloc(alignof(block_2secpar), VECTOR_COMMIT_LEAVES * sizeof(block_2secpar));
	vole_block* u =
		aligned_alloc(alignof(vole_block), VOLE_COL_BLOCKS * sizeof(vole_block));
	vole_block* v =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * VOLE_COL_BLOCKS * sizeof(vole_block));
	uint8_t vole_commit_check[VOLE_COMMIT_CHECK_SIZE];

	vole_commit(seed, iv, forest, hashed_leaves, u, v, signature, vole_commit_check);

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, vole_commit_check, VOLE_COMMIT_CHECK_SIZE);
	hash_update(&hasher, signature, VOLE_COMMIT_SIZE);
	hash_update(&hasher, &iv, sizeof(iv));
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t* vole_check_proof = signature + VOLE_COMMIT_SIZE;
	uint8_t vole_check_check[VOLE_CHECK_CHECK_BYTES];
	vole_check_sender(u, v, chal1, vole_check_proof, vole_check_check);

	uint8_t* correction = vole_check_proof + VOLE_CHECK_PROOF_BYTES;
	size_t remainder = (WITNESS_BITS / 8) % (16 * VOLE_BLOCK);
	for (size_t i = 0; i < WITNESS_BLOCKS - (remainder != 0); ++i)
	{
		vole_block correction_i = vole_block_xor(u[i], sk->witness[i]);
		memcpy(correction + i * sizeof(vole_block), &correction_i, sizeof(vole_block));
	}
	if (remainder)
	{
		vole_block correction_i = vole_block_xor(u[WITNESS_BLOCKS - 1], sk->witness[WITNESS_BLOCKS - 1]);
		memcpy(correction + (WITNESS_BLOCKS - 1) * sizeof(vole_block), &correction_i, remainder);
	}

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, chal1, sizeof(chal1));
    hash_update(&hasher, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
    hash_update(&hasher, vole_check_check, VOLE_CHECK_CHECK_BYTES);
    hash_update(&hasher, correction, WITNESS_BITS / 8);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), QUICKSILVER_ROWS_PADDED * sizeof(block_secpar));

	memcpy(&u[0], &sk->witness[0], WITNESS_BITS / 8);
	static_assert(QUICKSILVER_ROWS_PADDED % TRANSPOSE_BITS_ROWS == 0, "");
	transpose_secpar(v, macs, VOLE_COL_STRIDE, QUICKSILVER_ROWS_PADDED);
	free(v);

	quicksilver_state qs;
	quicksilver_init_prover(&qs, (uint8_t*) &u[0], macs, OWF_NUM_CONSTRAINTS, chal2);
	owf_constraints_prover(&qs, &sk->pk);

	uint8_t* qs_proof = correction + WITNESS_BITS / 8;
	uint8_t qs_check[QUICKSILVER_CHECK_BYTES];
	quicksilver_prove(&qs, WITNESS_BITS, qs_proof, qs_check);
	free(macs);
	free(u);

	uint8_t* veccom_open_start = qs_proof + QUICKSILVER_PROOF_BYTES;
	uint8_t* delta = veccom_open_start + VECTOR_COM_OPEN_SIZE;

#if COUNTER_BYTES == 0
	hash_init(&hasher);
	hash_update(&hasher, &chal2, sizeof(chal2));
	hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, delta, sizeof(block_secpar));

	uint8_t delta_bytes[SECURITY_PARAM];
	for (size_t i = 0; i < SECURITY_PARAM; ++i)
		delta_bytes[i] = expand_bit_to_byte(delta[i / 8], i % 8);
	vector_open(forest, hashed_leaves, delta_bytes, veccom_open_start);
	bool open_success = true;

#else
	uint32_t counter = 0;
	unsigned char hash_prefix[sizeof(chal2) + QUICKSILVER_PROOF_BYTES + QUICKSILVER_CHECK_BYTES];
	memcpy(hash_prefix, &chal2, sizeof(chal2));
	memcpy(hash_prefix + sizeof(chal2), qs_proof, QUICKSILVER_PROOF_BYTES);
	memcpy(hash_prefix + sizeof(chal2) + QUICKSILVER_PROOF_BYTES, qs_check, QUICKSILVER_CHECK_BYTES);
	bool open_success = force_vector_open(forest, hashed_leaves, delta, veccom_open_start, hash_prefix, sizeof(chal2) + QUICKSILVER_PROOF_BYTES + QUICKSILVER_CHECK_BYTES, &counter);
#endif

	free(forest);
	free(hashed_leaves);

	if (!open_success)
		return false;

	uint8_t* iv_dst = delta + sizeof(block_secpar);
	memcpy(iv_dst, &iv, sizeof(iv));

	// Always needed for assertion below.
	uint8_t* counter_dst = iv_dst + sizeof(iv);

#if COUNTER_BYTES > 0
	counter_dst[0] = counter;
	counter_dst[1] = counter>>8;
	counter_dst[2] = counter>>16;
	counter_dst[3] = counter>>24;
#else
	(void) counter_dst;
#endif

	assert(counter_dst + COUNTER_BYTES == signature + FAEST_SIGNATURE_BYTES);

	return true;
}

bool faest_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, const uint8_t* sk_packed,
	const uint8_t* random_seed, size_t random_seed_len)
{
	secret_key sk;
	uint8_t pk_packed[FAEST_PUBLIC_KEY_BYTES];
	if (!faest_unpack_sk_and_get_pubkey(pk_packed, sk_packed, &sk))
		return false;

	uint64_t attempt_num = 0;
	do
	{
		if (faest_sign_attempt(signature, msg, msg_len, &sk, &pk_packed[0],
			                   random_seed, random_seed_len, attempt_num))
		{
			faest_free_secret_key(&sk);
			return true;
		}
	} while (++attempt_num != 0);

	faest_free_secret_key(&sk);
	return false;
}

bool faest_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  const uint8_t* pk_packed)
{
	block128 iv;
	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_packed, FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, msg, msg_len);
	hash_update_byte(&hasher, 1);
	hash_final(&hasher, &mu, sizeof(mu));

	const uint8_t* vole_check_proof = signature + VOLE_COMMIT_SIZE;
	const uint8_t* correction = vole_check_proof + VOLE_CHECK_PROOF_BYTES;
	const uint8_t* qs_proof = correction + WITNESS_BITS / 8;
	const uint8_t* veccom_open_start = qs_proof + QUICKSILVER_PROOF_BYTES;
	const uint8_t* delta = veccom_open_start + VECTOR_COM_OPEN_SIZE;
	const uint8_t* iv_ptr = delta + sizeof(block_secpar);
#if COUNTER_BYTES > 0
	const uint8_t* counter = iv_ptr + sizeof(iv);
#endif

	uint8_t delta_bytes[SECURITY_PARAM];
	for (size_t i = 0; i < SECURITY_PARAM; ++i)
		delta_bytes[i] = expand_bit_to_byte(delta[i / 8], i % 8);

	vole_block* q =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * VOLE_COL_BLOCKS * sizeof(vole_block));
	uint8_t vole_commit_check[VOLE_COMMIT_CHECK_SIZE];

	memcpy(&iv, iv_ptr, sizeof(iv));
	bool reconstruct_success =  vole_reconstruct(iv, q, delta_bytes, signature, veccom_open_start, vole_commit_check);
	if (reconstruct_success == 0){
		free(q);
		return 0;
	}

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, vole_commit_check, VOLE_COMMIT_CHECK_SIZE);
	hash_update(&hasher, signature, VOLE_COMMIT_SIZE);
	hash_update(&hasher, &iv, sizeof(iv));
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t vole_check_check[VOLE_CHECK_CHECK_BYTES];
	vole_check_receiver(q, delta_bytes, chal1, vole_check_proof, vole_check_check);

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &chal1, sizeof(chal1));
	hash_update(&hasher, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	hash_update(&hasher, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	hash_update(&hasher, correction, WITNESS_BITS / 8);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	vole_block correction_blocks[WITNESS_BLOCKS];
	memcpy(&correction_blocks, correction, WITNESS_BITS / 8);
	memset(((uint8_t*) &correction_blocks) + WITNESS_BITS / 8, 0,
	       sizeof(correction_blocks) - WITNESS_BITS / 8);
	vole_receiver_apply_correction(WITNESS_BLOCKS, NONZERO_BITS_IN_CHALLENGE_3, correction_blocks, q, delta_bytes);

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), VOLE_ROWS_PADDED * sizeof(block_secpar));
	transpose_secpar(q, macs, VOLE_COL_STRIDE, QUICKSILVER_ROWS_PADDED);
	free(q);

	block_secpar delta_block;
	memcpy(&delta_block, delta, sizeof(delta_block));

	public_key pk;
	faest_unpack_public_key(&pk, pk_packed);

	quicksilver_state qs;
	quicksilver_init_verifier(&qs, macs, OWF_NUM_CONSTRAINTS, delta_block, chal2);
	owf_constraints_verifier(&qs, &pk);

	faest_free_public_key(&pk);

	uint8_t qs_check[QUICKSILVER_CHECK_BYTES];
	quicksilver_verify(&qs, WITNESS_BITS, qs_proof, qs_check);
	free(macs);

	block_secpar delta_check;
	hash_init(&hasher);
	hash_update(&hasher, &chal2, sizeof(chal2));
	hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
#if COUNTER_BYTES > 0
	hash_update(&hasher, counter, COUNTER_BYTES);
#endif
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &delta_check, sizeof(delta_check));

	return memcmp(delta, &delta_check, sizeof(delta_check)) == 0;
}
