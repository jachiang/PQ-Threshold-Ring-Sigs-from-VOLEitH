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
#include <stdio.h> // JC: For debugging.

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

	if (!faest_compute_witness(unpacked, ring, false))
	{
		faest_free_secret_key(unpacked);
		return false;
	}

	return true;
}

// TODO: This extends faest_unpack_secret_key.
#if (TAGGED_RING_PK_OWF_NUM == 2)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1)
#elif (TAGGED_RING_PK_OWF_NUM == 3)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1, const uint8_t* owf_input2)
#elif (TAGGED_RING_PK_OWF_NUM == 4)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1, const uint8_t* owf_input2, const uint8_t* owf_input3)
#endif
{
	// AES: owf_inputs are fixed, and owf_key is identical for all 4 owf.
	// EM: owf_keys are fixed, and owf_inputs are identical for all 4 owf.

	// Copy owf inputs and key to sk.
	memcpy(&unpacked_sk->pk.owf_input, owf_input0, sizeof(unpacked_sk->pk.owf_input));
	memcpy(&unpacked_sk->pk1.owf_input, owf_input1, sizeof(unpacked_sk->pk1.owf_input));
	#if (TAGGED_RING_PK_OWF_NUM > 2)
	memcpy(&unpacked_sk->pk2.owf_input, owf_input2, sizeof(unpacked_sk->pk2.owf_input));
	#endif
	#if (TAGGED_RING_PK_OWF_NUM > 3)
	memcpy(&unpacked_sk->pk3.owf_input, owf_input3, sizeof(unpacked_sk->pk3.owf_input));
	#endif
	memcpy(&unpacked_sk->sk, owf_key, sizeof(unpacked_sk->sk));
	// Generate round keys in sk.
#if defined(OWF_AES_CTR)
	aes_keygen(&unpacked_sk->round_keys, unpacked_sk->sk);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked_sk->pk.fixed_key, unpacked_sk->pk.owf_input[0]);
	rijndael_keygen(&unpacked_sk->pk1.fixed_key, unpacked_sk->pk1.owf_input[0]);
	#if (TAGGED_RING_PK_OWF_NUM > 2)
	rijndael_keygen(&unpacked_sk->pk2.fixed_key, unpacked_sk->pk2.owf_input[0]);
	#endif
	#if (TAGGED_RING_PK_OWF_NUM > 3)
	rijndael_keygen(&unpacked_sk->pk3.fixed_key, unpacked_sk->pk3.owf_input[0]);
	#endif
#else
#error "Unsupported OWF."
#endif
	// Computes pk owf output to sk.
	if (!faest_compute_witness(unpacked_sk, true, true))
	{
		return false;
	}

	return true;
}

// JC: Intended to be called on sk generated in faest_unpack_secret_key_fixed_owf_inputs.
bool faest_unpack_secret_key_for_tag_alt(secret_key* unpacked_sk, const uint8_t* tag_owf_input0, const uint8_t* tag_owf_input1)
{
	memcpy(&unpacked_sk->tag.owf_input, tag_owf_input0, sizeof(unpacked_sk->tag.owf_input));
	memcpy(&unpacked_sk->tag1.owf_input, tag_owf_input1, sizeof(unpacked_sk->tag1.owf_input));
#if defined(OWF_AES_CTR)
	aes_keygen(&unpacked_sk->round_keys, unpacked_sk->sk);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked_sk->tag.fixed_key, unpacked_sk->tag.owf_input[0]);
	rijndael_keygen(&unpacked_sk->tag1.fixed_key, unpacked_sk->tag1.owf_input[0]);
#else
#error "Unsupported OWF."
#endif
	if (!faest_compute_witness(unpacked_sk, true, true))
	{
		return false;
	}
	return true;
}

// JC: Intended to be called on sk generated in faest_unpack_secret_key_fixed_owf_inputs.
bool faest_unpack_secret_key_for_tag(secret_key* unpacked_sk, const uint8_t* tag_owf_input0)
{
	memcpy(&unpacked_sk->tag.owf_input, tag_owf_input0, sizeof(unpacked_sk->tag.owf_input));
	// memcpy(&unpacked_sk->tag1.owf_input, tag_owf_input1, sizeof(unpacked_sk->tag1.owf_input));
#if defined(OWF_AES_CTR)
	aes_keygen(&unpacked_sk->round_keys, unpacked_sk->sk);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked_sk->tag.fixed_key, unpacked_sk->tag.owf_input[0]);
	// rijndael_keygen(&unpacked_sk->tag1.fixed_key, unpacked_sk->tag1.owf_input[0]);
#else
#error "Unsupported OWF."
#endif
	if (!faest_compute_witness_tag(unpacked_sk, true, true))
	{
		return false;
	}
	return true;
}


#if defined(OWF_AES_CTR)
bool faest_unpack_secret_key_for_cbc_tag(secret_key* unpacked_sk, const uint8_t* tag_owf_input0, const uint8_t* tag_owf_input1, const uint8_t* tag_owf_input2, const uint8_t* tag_owf_input3)
{
	memcpy(&unpacked_sk->tag_cbc.owf_inputs[0], tag_owf_input0, sizeof(unpacked_sk->tag_cbc.owf_inputs[0]));
	memcpy(&unpacked_sk->tag_cbc.owf_inputs[1], tag_owf_input1, sizeof(unpacked_sk->tag_cbc.owf_inputs[1]));
	if (CBC_TAGGED_RING_TAG_OWF_NUM > 2) {
		memcpy(&unpacked_sk->tag_cbc.owf_inputs[2], tag_owf_input2, sizeof(unpacked_sk->tag_cbc.owf_inputs[2]));
	}
	if (CBC_TAGGED_RING_TAG_OWF_NUM > 3) {
		memcpy(&unpacked_sk->tag_cbc.owf_inputs[3], tag_owf_input3, sizeof(unpacked_sk->tag_cbc.owf_inputs[3]));
	}
#if defined(OWF_AES_CTR)
	aes_keygen(&unpacked_sk->round_keys, unpacked_sk->sk);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked_sk->tag.fixed_key, unpacked_sk->tag.owf_input[0]);
	rijndael_keygen(&unpacked_sk->tag1.fixed_key, unpacked_sk->tag1.owf_input[0]);
#else
#error "Unsupported OWF."
#endif
	if (!faest_compute_witness_cbc_tag(unpacked_sk, true, true))
	{
		return false;
	}
	return true;
}
#endif

// nothing to do here i guess
void faest_pack_public_key(uint8_t* packed, const public_key* unpacked)
{
	memcpy(packed, &unpacked->owf_input, sizeof(unpacked->owf_input));
	memcpy(packed + sizeof(unpacked->owf_input), &unpacked->owf_output[0], sizeof(unpacked->owf_output));
}

#if defined(OWF_AES_CTR)
void faest_pack_cbc_tag(uint8_t* packed, const cbc_tag* unpacked, size_t owf_num)
{
	for (size_t i = 0; i < owf_num; ++i)
	{
		memcpy(packed + i * sizeof(unpacked->owf_inputs[0]), &unpacked->owf_inputs[i], sizeof(unpacked->owf_inputs[0]));
	}
	memcpy(packed + owf_num * sizeof(unpacked->owf_inputs[0]), &unpacked->owf_output[0], sizeof(unpacked->owf_output));
}
#endif

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

void faest_pack_pk_ring(uint8_t* pk_ring_packed, const public_key_ring* pk_ring_unpacked)
{
    uint8_t* pk_ptr = pk_ring_packed;
    for (uint32_t i = 0; i < FAEST_RING_SIZE; ++i) {
		faest_pack_public_key(pk_ptr, &pk_ring_unpacked->pubkeys[i]);
		pk_ptr = pk_ptr + FAEST_PUBLIC_KEY_BYTES;
    }
}

// done
bool faest_compute_witness(secret_key* sk, bool ring, bool tag)
{
	uint8_t* w_ptr;
	if (!ring) {
		w_ptr = (uint8_t*) &sk->witness;
	}
	else if (ring && !tag) {
		w_ptr = (uint8_t*) &sk->ring_witness;
	}
	else if (ring && tag) {
		w_ptr = (uint8_t*) &sk->tagged_ring_witness;
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
		// if ((sbox_output - 0x01010101) & ~sbox_output & 0x80808080)
		// 	return false;
	}
#endif

size_t owf_num;
if (tag){
	owf_num = TAGGED_RING_PK_OWF_NUM + TAGGED_RING_TAG_OWF_NUM; // Always 2 + 2?
}
else{
	owf_num = 1;
}
bool tag_itr = false;
// JC: Witness expansion for each active-pk-OWF and tag-OWF.
for (size_t owf = 0; owf < owf_num; ++owf) {
	// printf("OWF loop begin: %u\n", owf);

	// Skip final iteration if not tag ring sig.
	// if (owf == owf_num) {
	// if (owf  > TAGGED_RING_PK_OWF_NUM - 1) {
	// 	if (tag) {
	// 		tag_itr = true;
	// 	}
	// 	else {
	// 		break;
	// 	}
	// }

	// if (tag_itr) {
	// 	size_t offset = (w_ptr - (uint8_t*) &sk->tagged_ring_witness);
	// 	printf("Tag witness offset: %u\n", offset);
	// }

#if defined(OWF_AES_CTR)
	for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
	{
		if (owf == 0) {
			sk->pk.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->pk.owf_input[i]);
		}
		else if (owf == 1) {
			sk->pk1.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->pk1.owf_input[i]);
		}
		else if (owf == 2) {
			sk->tag.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->tag.owf_input[i]);
		}
		else if (owf == 3) {
			sk->tag1.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->tag1.owf_input[i]);
		}
	}
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	static_assert(OWF_BLOCKS == 1, "");
	if (owf == 0) {
		sk->pk.owf_output[0] = owf_block_xor(sk->pk.fixed_key.keys[0], sk->sk);
	}
	else if (owf == 1) {
		sk->pk1.owf_output[0] = owf_block_xor(sk->pk1.fixed_key.keys[0], sk->sk);
	}
	else if (owf == 2) {
		sk->tag.owf_output[0] = owf_block_xor(sk->tag.fixed_key.keys[0], sk->sk);
	}
	else if (owf == 3) {
		sk->tag1.owf_output[0] = owf_block_xor(sk->tag1.fixed_key.keys[0], sk->sk);
	}
#elif defined(OWF_RAIN_3)	// This should be similar to EM, except I will add the sk later in the round function call
	// JC: Not supported for tagged ring sigs.
	static_assert(OWF_BLOCKS == 1, "");
	sk->pk.owf_output[0] = sk->pk.owf_input[0];
#elif defined(OWF_RAIN_4)	// This should be similar to EM, except I will add the sk later in the round function call
	// JC: Not supported for tagged ring sigs.
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
			if (owf == 0) {
				aes_round_function(&sk->round_keys, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				aes_round_function(&sk->round_keys, &sk->pk1.owf_output[i], &after_sbox, round);
			}
			else if (owf == 2) {
				aes_round_function(&sk->round_keys, &sk->tag.owf_output[i], &after_sbox, round);
			}
			else if (owf == 3) {
				aes_round_function(&sk->round_keys, &sk->tag1.owf_output[i], &after_sbox, round);
			}
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	#if SECURITY_PARAM == 128
			if (owf == 0) {
				aes_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				aes_round_function(&sk->pk1.fixed_key, &sk->pk1.owf_output[i], &after_sbox, round);
			}
			else if (owf == 2) {
				aes_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			else if (owf == 3) {
				aes_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			}
	#elif SECURITY_PARAM == 192
			if (owf == 0) {
				rijndael192_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				rijndael192_round_function(&sk->pk1.fixed_key, &sk->pk1.owf_output[i], &after_sbox, round);
			}
			else if (owf == 2) {
				rijndael192_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			else if (owf == 3) {
				rijndael192_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			}
	#elif SECURITY_PARAM == 256
			if (owf == 0) {
				rijndael256_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				rijndael256_round_function(&sk->pk1.fixed_key, &sk->pk1.owf_output[i], &after_sbox, round);
			}
			else if (owf == 2) {
				rijndael256_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			else if (owf == 3) {
				rijndael256_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			}
	#endif
#elif defined(OWF_RAIN_3)
	// JC: Not supported for tagged ring sigs.
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
	// JC: Not supported for tagged ring sigs.
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
	{
		if (owf == 0) {
			sk->pk.owf_output[i] = owf_block_xor(sk->pk.owf_output[i], sk->sk);
		}
		else if (owf == 1) {
			sk->pk1.owf_output[i] = owf_block_xor(sk->pk1.owf_output[i], sk->sk);
		}
		else if (owf == 2) {
			sk->tag.owf_output[i] = owf_block_xor(sk->tag.owf_output[i], sk->sk);
		}
		else if (owf == 3) {
			sk->tag1.owf_output[i] = owf_block_xor(sk->tag1.owf_output[i], sk->sk);
		}
	}
#endif

#endif
	// printf("OWF loop end: %u\n", owf);
	} // End of loop over OWF 1-4.

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

		// JC: Copy 1-hotvector serialization to witness.
		memcpy(w_ptr, hotvectors_bytes, (FAEST_RING_HOTVECTOR_BITS * FAEST_RING_HOTVECTOR_DIM + 7) / 8);
	}
	return true;
}


bool faest_compute_witness_tag(secret_key* sk, bool ring, bool tag) // tagged sig.
{
	// TODO: Placeholder. Dedicate this function to tagged sigs.
	tag = true; ring = false;

	uint8_t* w_ptr = (uint8_t*) &sk->tagged_witness;
	// if (!ring) {
	// 	w_ptr = (uint8_t*) &sk->witness;
	// }
	// else if (ring && !tag) {
	// 	w_ptr = (uint8_t*) &sk->ring_witness;
	// }
	// else if (ring && tag) {
	// 	w_ptr = (uint8_t*) &sk->tagged_ring_witness;
	// }

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
		// if ((sbox_output - 0x01010101) & ~sbox_output & 0x80808080)
		// 	return false;
	}
#endif

size_t owf_num = 2;
// if (tag){
// 	owf_num = TAGGED_RING_PK_OWF_NUM + TAGGED_RING_TAG_OWF_NUM; // Always 2 + 2?
// }
// else{
// 	owf_num = 1;
// }
bool tag_itr = false;
// JC: Witness expansion for each active-pk-OWF and tag-OWF.
for (size_t owf = 0; owf < owf_num; ++owf) {
	// printf("OWF loop begin: %u\n", owf);

	// Skip final iteration if not tag ring sig.
	// if (owf == owf_num) {
	// if (owf  > TAGGED_RING_PK_OWF_NUM - 1) {
	// 	if (tag) {
	// 		tag_itr = true;
	// 	}
	// 	else {
	// 		break;
	// 	}
	// }

	// if (tag_itr) {
	// 	size_t offset = (w_ptr - (uint8_t*) &sk->tagged_ring_witness);
	// 	printf("Tag witness offset: %u\n", offset);
	// }

#if defined(OWF_AES_CTR)
	for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
	{
		if (owf == 0) {
			sk->pk.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->pk.owf_input[i]);
		}
		else if (owf == 1) {
			// sk->pk.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->pk.owf_input[i]);
			sk->tag.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->tag.owf_input[i]);
		}
		// else if (owf == 2) {
		// 	sk->tag.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->tag.owf_input[i]);
		// }
		// else if (owf == 3) {
		// 	sk->tag1.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->tag1.owf_input[i]);
		// }
	}
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	static_assert(OWF_BLOCKS == 1, "");
	if (owf == 0) {
		sk->pk.owf_output[0] = owf_block_xor(sk->pk.fixed_key.keys[0], sk->sk);
	}
	else if (owf == 1) {
		// TODO: Migrate to tag pk.
		// sk->pk.owf_output[0] = owf_block_xor(sk->pk.fixed_key.keys[0], sk->sk);
		sk->tag.owf_output[0] = owf_block_xor(sk->tag.fixed_key.keys[0], sk->sk);
	}
	// else if (owf == 2) {
	// 	sk->tag.owf_output[0] = owf_block_xor(sk->tag.fixed_key.keys[0], sk->sk);
	// }
	// else if (owf == 3) {
	// 	sk->tag1.owf_output[0] = owf_block_xor(sk->tag1.fixed_key.keys[0], sk->sk);
	// }
#elif defined(OWF_RAIN_3)	// This should be similar to EM, except I will add the sk later in the round function call
	// JC: Not supported for tagged ring sigs.
	static_assert(OWF_BLOCKS == 1, "");
	sk->pk.owf_output[0] = sk->pk.owf_input[0];
#elif defined(OWF_RAIN_4)	// This should be similar to EM, except I will add the sk later in the round function call
	// JC: Not supported for tagged ring sigs.
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
			if (owf == 0) {
				aes_round_function(&sk->round_keys, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				// aes_round_function(&sk->round_keys, &sk->pk.owf_output[i], &after_sbox, round);
				aes_round_function(&sk->round_keys, &sk->tag.owf_output[i], &after_sbox, round);
			}
			// else if (owf == 2) {
			// 	aes_round_function(&sk->round_keys, &sk->tag.owf_output[i], &after_sbox, round);
			// }
			// else if (owf == 3) {
			// 	aes_round_function(&sk->round_keys, &sk->tag1.owf_output[i], &after_sbox, round);
			// }
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	#if SECURITY_PARAM == 128
			if (owf == 0) {
				aes_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				// aes_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
				aes_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			// else if (owf == 2) {
			// 	aes_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			// }
			// else if (owf == 3) {
			// 	aes_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			// }
	#elif SECURITY_PARAM == 192
			if (owf == 0) {
				rijndael192_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				// rijndael192_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
				rijndael192_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			// else if (owf == 2) {
			// 	rijndael192_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			// }
			// else if (owf == 3) {
			// 	rijndael192_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			// }
	#elif SECURITY_PARAM == 256
			if (owf == 0) {
				rijndael256_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				// rijndael256_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
				rijndael256_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			// else if (owf == 2) {
			// 	rijndael256_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			// }
			// else if (owf == 3) {
			// 	rijndael256_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			// }
	#endif
#elif defined(OWF_RAIN_3)
	// JC: Not supported for tagged ring sigs.
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
	// JC: Not supported for tagged ring sigs.
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
	} // End of rounds.

	// Offset witness pointer for next OWF.
	w_ptr += (OWF_BLOCKS - 1) * sizeof(owf_block) * (OWF_ROUNDS - 1);

#if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
	{
		if (owf == 0) {
			sk->pk.owf_output[i] = owf_block_xor(sk->pk.owf_output[i], sk->sk);
		}
		else if (owf == 1) {
			// sk->pk.owf_output[i] = owf_block_xor(sk->pk.owf_output[i], sk->sk);
			sk->tag.owf_output[i] = owf_block_xor(sk->tag.owf_output[i], sk->sk);
		}
		// else if (owf == 2) {
		// 	sk->tag.owf_output[i] = owf_block_xor(sk->tag.owf_output[i], sk->sk);
		// }
		// else if (owf == 3) {
		// 	sk->tag1.owf_output[i] = owf_block_xor(sk->tag1.owf_output[i], sk->sk);
		// }
	}
#endif

#endif
	// printf("OWF loop end: %u\n", owf);
	} // End of loop over OWF 1-4.

	// if(false) {
	// 	assert(w_ptr - (uint8_t*) &sk->witness == WITNESS_BITS / 8);
	// 	memset(w_ptr, 0, sizeof(sk->witness) - WITNESS_BITS / 8);
	// }
	// else {
	// 	// JC: Decompose active branch index (according to hotvector size/dim).
	// 	uint32_t base = FAEST_RING_HOTVECTOR_BITS + 1;
	// 	uint32_t decomp[FAEST_RING_HOTVECTOR_DIM] = {0};
	// 	base_decompose(sk->idx, base, decomp, FAEST_RING_HOTVECTOR_DIM);

	// 	// JC: Serialization of hotvectors as bytes.
	// 	uint8_t hotvectors_bytes[(FAEST_RING_HOTVECTOR_BITS * FAEST_RING_HOTVECTOR_DIM + 7) / 8] = {0};

	// 	// JC: Init indices and vars.
	// 	int curr_byte_idx = 0;
	// 	int curr_bit_idx = 0;

	// 	for (int i = 0; i < FAEST_RING_HOTVECTOR_DIM; ++i) {
	// 		// JC: Remaining free bits in current byte.
	// 		int remaining_bits = 8 - curr_bit_idx;
	// 		if ((decomp[i] != base - 1)) {
	// 			// JC: Hotvector has exactly one active bit.
	// 			uint32_t hotvector_idx = decomp[i];
	// 			int active_bit_idx = (curr_bit_idx + hotvector_idx) % 8;
	// 			int active_byte_idx = curr_byte_idx;
	// 			if (hotvector_idx + 1 > remaining_bits) {
	// 				active_byte_idx = ((hotvector_idx - remaining_bits + 7 + 1) / 8) + curr_byte_idx;
	// 			}
	// 			// printf("Active byte idx: %u \n", active_byte_idx);
	// 			// printf("Active bit idx: %u \n", active_bit_idx);

	// 			// JC: Activate bit in hotvectors byte array.
	// 			hotvectors_bytes[active_byte_idx] = hotvectors_bytes[active_byte_idx] ^ (1 << (active_bit_idx));
	// 		}
	// 		// else{
	// 		// 	if (decomp[i] == base - 1) {
	// 		// 		printf("Last active bit omitted in hotvector %u\n", i);
	// 		// 	}
	// 		// }
	// 		// // JC: Update indices vars.
	// 		curr_byte_idx = (FAEST_RING_HOTVECTOR_BITS - remaining_bits + 7) / 8 + curr_byte_idx;
	// 		curr_bit_idx = (curr_bit_idx + FAEST_RING_HOTVECTOR_BITS) % 8;
	// 	}

	// 	// JC: Copy 1-hotvector serialization to witness.
	// 	memcpy(w_ptr, hotvectors_bytes, (FAEST_RING_HOTVECTOR_BITS * FAEST_RING_HOTVECTOR_DIM + 7) / 8);
	// }
	return true;
}


// Support CBC only in AES mode.
#if defined(OWF_AES_CTR)
bool faest_compute_witness_cbc_tag(secret_key* sk, bool ring, bool tag)
{
	uint8_t* w_ptr;
	if (!ring) {
		w_ptr = (uint8_t*) &sk->witness;
	}
	else if (ring && !tag) {
		w_ptr = (uint8_t*) &sk->ring_witness;
	}
	else if (ring && tag) {
		w_ptr = (uint8_t*) &sk->cbc_tagged_ring_witness;
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
		// if ((sbox_output - 0x01010101) & ~sbox_output & 0x80808080)
		// 	return false;
	}
#endif

size_t owf_num;
if (tag){
	owf_num = TAGGED_RING_PK_OWF_NUM + CBC_TAGGED_RING_TAG_OWF_NUM; // Always 2 + 2?
}
else{
	owf_num = 1;
}
bool tag_itr = false;
// JC: Witness expansion for each active-pk-OWF and tag-OWF.
for (size_t owf = 0; owf < owf_num; ++owf) {
	// printf("OWF loop begin: %u\n", owf);

	// Skip final iteration if not tag ring sig.
	// if (owf == owf_num) {
	// if (owf  > TAGGED_RING_PK_OWF_NUM - 1) {
	// 	if (tag) {
	// 		tag_itr = true;
	// 	}
	// 	else {
	// 		break;
	// 	}
	// }

	// if (tag_itr) {
	// 	size_t offset = (w_ptr - (uint8_t*) &sk->tagged_ring_witness);
	// 	printf("Tag witness offset: %u\n", offset);
	// }

#if defined(OWF_AES_CTR)
	// PK: Initial XOR with keys.
	for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
	{
		if (owf == 0) {
			sk->pk.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->pk.owf_input[i]);
		}
		else if (owf == 1) {
			sk->pk1.owf_output[i] = owf_block_xor(sk->round_keys.keys[0], sk->pk1.owf_input[i]);
		}
	}
	// Tag: Initial XOR with keys.
	if (owf > TAGGED_RING_PK_OWF_NUM - 1) {
		size_t tag_owf = owf - TAGGED_RING_PK_OWF_NUM;
		if (tag_owf == 0) {
			// Set msb bit of input block to 1 prior to XOR with round keys.
			sk->tag_cbc.owf_outputs[0] = owf_block_xor(sk->round_keys.keys[0], block128_activate_msb(sk->tag_cbc.owf_inputs[0]));

			// uint8_t bytes[16];
			// _mm_storeu_si128((__m128i *)bytes, block128_activate_msb(sk->tag_cbc.owf_inputs[0]));
			// uint8_t bytes1[16];
			// _mm_storeu_si128((__m128i *)bytes1, sk->tag_cbc.owf_inputs[0]);
			// printf("First OWF input bytes: ");
			// for (int i = 0; i < 16; i++) {
			// 	printf("%02X ", bytes[i]); // Print each byte in hex
			// 	printf("%02X ", bytes1[i]); // Print each byte in hex
			// }
			// printf("\n");
		}
		else if (tag_owf > 0)
		{
			// Set msb bit of block to 1 after XOR with cbc state.
			sk->tag_cbc.owf_outputs[tag_owf] = block128_activate_msb(owf_block_xor(sk->tag_cbc.owf_outputs[tag_owf-1], sk->tag_cbc.owf_inputs[tag_owf]));
			sk->tag_cbc.owf_outputs[tag_owf] = owf_block_xor(sk->round_keys.keys[0], sk->tag_cbc.owf_outputs[tag_owf]);
		}
	}

#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	static_assert(OWF_BLOCKS == 1, "");
	if (owf == 0) {
		sk->pk.owf_output[0] = owf_block_xor(sk->pk.fixed_key.keys[0], sk->sk);
	}
	else if (owf == 1) {
		sk->pk1.owf_output[0] = owf_block_xor(sk->pk1.fixed_key.keys[0], sk->sk);
	}
	else if (owf == 2) {
		sk->tag.owf_output[0] = owf_block_xor(sk->tag.fixed_key.keys[0], sk->sk);
	}
	else if (owf == 3) {
		sk->tag1.owf_output[0] = owf_block_xor(sk->tag1.fixed_key.keys[0], sk->sk);
	}
#elif defined(OWF_RAIN_3)	// This should be similar to EM, except I will add the sk later in the round function call
	// JC: Not supported for tagged ring sigs.
	static_assert(OWF_BLOCKS == 1, "");
	sk->pk.owf_output[0] = sk->pk.owf_input[0];
#elif defined(OWF_RAIN_4)	// This should be similar to EM, except I will add the sk later in the round function call
	// JC: Not supported for tagged ring sigs.
	static_assert(OWF_BLOCKS == 1, "");
	sk->pk.owf_output[0] = sk->pk.owf_input[0];
#endif

	for (unsigned int round = 1; round <= OWF_ROUNDS; ++round)
	{
		owf_block after_sbox;
		for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
		{
			#if !defined(ALLOW_ZERO_SBOX) && (defined(OWF_AES_CTR) || defined(OWF_RIJNDAEL_EVEN_MANSOUR))
			// The block is about to go into the SBox, so check for zeros.
			if (owf_block_any_zeros(sk->pk.owf_output[i]))
				return false;
			#endif

#if defined(OWF_AES_CTR)
			if (owf == 0) {
				aes_round_function(&sk->round_keys, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				aes_round_function(&sk->round_keys, &sk->pk1.owf_output[i], &after_sbox, round);
			}
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	#if SECURITY_PARAM == 128
			if (owf == 0) {
				aes_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				aes_round_function(&sk->pk1.fixed_key, &sk->pk1.owf_output[i], &after_sbox, round);
			}
			else if (owf == 2) {
				aes_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			else if (owf == 3) {
				aes_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			}
	#elif SECURITY_PARAM == 192
			if (owf == 0) {
				rijndael192_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				rijndael192_round_function(&sk->pk1.fixed_key, &sk->pk1.owf_output[i], &after_sbox, round);
			}
			else if (owf == 2) {
				rijndael192_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			else if (owf == 3) {
				rijndael192_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			}
	#elif SECURITY_PARAM == 256
			if (owf == 0) {
				rijndael256_round_function(&sk->pk.fixed_key, &sk->pk.owf_output[i], &after_sbox, round);
			}
			else if (owf == 1) {
				rijndael256_round_function(&sk->pk1.fixed_key, &sk->pk1.owf_output[i], &after_sbox, round);
			}
			else if (owf == 2) {
				rijndael256_round_function(&sk->tag.fixed_key, &sk->tag.owf_output[i], &after_sbox, round);
			}
			else if (owf == 3) {
				rijndael256_round_function(&sk->tag1.fixed_key, &sk->tag1.owf_output[i], &after_sbox, round);
			}
	#endif
#elif defined(OWF_RAIN_3)
	// JC: Not supported for tagged ring sigs.
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
	// JC: Not supported for tagged ring sigs.
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
		} // End of owf_block loop.

		// Move tag round function outside owf_block loop.
		if (owf > TAGGED_RING_PK_OWF_NUM - 1){
			aes_round_function(&sk->round_keys, &sk->tag_cbc.owf_outputs[owf-TAGGED_RING_PK_OWF_NUM], &after_sbox, round);
			// Copy state except last round and last tag owf.
			// if (round < OWF_ROUNDS)
			// 	memcpy(w_ptr, &after_sbox, sizeof(owf_block));
			if (!(round == OWF_ROUNDS && owf == owf_num-1)) {
				memcpy(w_ptr, &after_sbox, sizeof(owf_block));
			}
		}
		// if (owf == 2) {
		// 	aes_round_function(&sk->round_keys, &sk->tag.owf_output[0], &after_sbox, round);
		// 	if (round < OWF_ROUNDS)
		// 		memcpy(w_ptr, &after_sbox, sizeof(owf_block));
		// }
		// else if (owf == 3) {
		// 	aes_round_function(&sk->round_keys, &sk->tag1.owf_output[0], &after_sbox, round);
		// 	if (round < OWF_ROUNDS)
		// 		memcpy(w_ptr, &after_sbox, sizeof(owf_block));
		// }

		// PK: Witness pointer offset for all but last round.
		if (owf < TAGGED_RING_PK_OWF_NUM) {
			if (round < OWF_ROUNDS)
				w_ptr += sizeof(owf_block);
		}
		// Tag: Witness pointer offset for all but last round in last owf.
		else {
			if (!(round == OWF_ROUNDS && owf == owf_num-1)) {
				w_ptr += sizeof(owf_block);
			}
		}

	}
	// At end of pk owf, offset pointer to account for multiple owf blocks.
	if (owf < TAGGED_RING_PK_OWF_NUM) {
		w_ptr += (OWF_BLOCKS - 1) * sizeof(owf_block) * (OWF_ROUNDS - 1);
	}

#if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	for (uint32_t i = 0; i < OWF_BLOCKS; ++i)
	{
		if (owf == 0) {
			sk->pk.owf_output[i] = owf_block_xor(sk->pk.owf_output[i], sk->sk);
		}
		else if (owf == 1) {
			sk->pk1.owf_output[i] = owf_block_xor(sk->pk1.owf_output[i], sk->sk);
		}
		else if (owf == 2) {
			sk->tag.owf_output[i] = owf_block_xor(sk->tag.owf_output[i], sk->sk);
		}
		else if (owf == 3) {
			sk->tag1.owf_output[i] = owf_block_xor(sk->tag1.owf_output[i], sk->sk);
		}
	}
#endif

#endif
	// printf("OWF loop end: %u\n", owf);
	} // End of loop over OWF 1-4.

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

		// JC: Copy 1-hotvector serialization to witness.
		memcpy(w_ptr, hotvectors_bytes, (FAEST_RING_HOTVECTOR_BITS * FAEST_RING_HOTVECTOR_DIM + 7) / 8);
	}
	return true;
}
#endif

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
	vole_check_sender(u, v, chal1, vole_check_proof, vole_check_check, QUICKSILVER_ROWS, VOLE_COL_BLOCKS);

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
	vole_check_receiver(q, delta_bytes, chal1, vole_check_proof, vole_check_check, QUICKSILVER_ROWS, VOLE_COL_BLOCKS);

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
	vole_receiver_apply_correction(WITNESS_BLOCKS, NONZERO_BITS_IN_CHALLENGE_3, correction_blocks, q, delta_bytes, VOLE_COL_BLOCKS);

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

static bool faest_ring_sign_attempt(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, const secret_key* sk,
	const public_key_ring* pk_ring, const uint8_t* random_seed, size_t random_seed_len, uint64_t attempt_num)
{
// static bool faest_ring_sign_attempt(
// 	uint8_t* signature, const uint8_t* msg, size_t msg_len,
// 	const secret_key* sk, const uint8_t* pk_packed,
// 	const uint8_t* random_seed, size_t random_seed_len, uint64_t attempt_num)
// {
    uint8_t* pk_ring_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	faest_pack_pk_ring(pk_ring_packed, pk_ring); // TODO - EM mode.

	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_ring_packed, FAEST_RING_SIZE * FAEST_PUBLIC_KEY_BYTES);
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
		aligned_alloc(alignof(vole_block), VOLE_RING_COL_BLOCKS * sizeof(vole_block));
	vole_block* v =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * VOLE_RING_COL_BLOCKS * sizeof(vole_block));
	uint8_t vole_commit_check[VOLE_COMMIT_CHECK_SIZE];

	vole_commit_for_ring(seed, iv, forest, hashed_leaves, u, v, signature, vole_commit_check);

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, vole_commit_check, VOLE_COMMIT_CHECK_SIZE);
	hash_update(&hasher, signature, VOLE_RING_COMMIT_SIZE); // JC: check VOLE_RING_COMMIT_SIZE
	hash_update(&hasher, &iv, sizeof(iv));
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t* vole_check_proof = signature + VOLE_RING_COMMIT_SIZE; // JC: check VOLE_RING_COMMIT_SIZE

	uint8_t vole_check_check[VOLE_CHECK_CHECK_BYTES];
	vole_check_sender(u, v, chal1, vole_check_proof, vole_check_check, QUICKSILVER_RING_ROWS, VOLE_RING_COL_BLOCKS);

	// printf("Prover chall 1:");
    // for (size_t i = 0; i < VOLE_CHECK_CHALLENGE_BYTES; i++) {
    //     printf("%02x", chal1[i]);
	// }
	// printf("\n");

	uint8_t vole_check_proof_test[VOLE_CHECK_PROOF_BYTES];
	uint8_t vole_check_check_test[VOLE_CHECK_CHECK_BYTES];
	memcpy(&vole_check_proof_test, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	memcpy(&vole_check_check_test, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	// printf("Prover check proof:");
    // for (size_t i = 0; i < QUICKSILVER_CHALLENGE_BYTES; i++) {
    //     printf("%02x", vole_check_proof_test[i]);
	// }
	// printf("\n");
	// printf("Prover check check:");
    // for (size_t i = 0; i < QUICKSILVER_CHALLENGE_BYTES; i++) {
    //     printf("%02x", vole_check_check_test[i]);
	// }
	// printf("\n");

	uint8_t* correction = vole_check_proof + VOLE_CHECK_PROOF_BYTES;
	size_t remainder = (RING_WITNESS_BITS / 8) % (16 * VOLE_BLOCK);
	for (size_t i = 0; i < RING_WITNESS_BLOCKS - (remainder != 0); ++i)
	{
		vole_block correction_i = vole_block_xor(u[i], sk->ring_witness[i]);
		memcpy(correction + i * sizeof(vole_block), &correction_i, sizeof(vole_block));
	}
	if (remainder)
	{
		vole_block correction_i = vole_block_xor(u[RING_WITNESS_BLOCKS - 1], sk->ring_witness[RING_WITNESS_BLOCKS - 1]);
		memcpy(correction + (RING_WITNESS_BLOCKS - 1) * sizeof(vole_block), &correction_i, remainder);
	}

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, chal1, sizeof(chal1));
    hash_update(&hasher, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
    hash_update(&hasher, vole_check_check, VOLE_CHECK_CHECK_BYTES);
    hash_update(&hasher, correction, RING_WITNESS_BITS / 8);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	// printf("Prover chall 2:");
    // for (size_t i = 0; i < QUICKSILVER_CHALLENGE_BYTES; i++) {
    //     printf("%02x", chal2[i]);
	// }
	// printf("\n");

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), QUICKSILVER_RING_ROWS_PADDED * sizeof(block_secpar));

	memcpy(&u[0], &sk->ring_witness[0], RING_WITNESS_BITS / 8);
	static_assert(QUICKSILVER_RING_ROWS_PADDED % TRANSPOSE_BITS_ROWS == 0, "");
	transpose_secpar(v, macs, VOLE_RING_COL_STRIDE, QUICKSILVER_RING_ROWS_PADDED);
	free(v);

	quicksilver_state qs;
	// quicksilver_init_prover(&qs, (uint8_t*) &u[0], macs, OWF_NUM_CONSTRAINTS, chal2);
	// owf_constraints_prover(&qs, &sk->pk);
	quicksilver_init_or_prover(&qs, (uint8_t*) &u[0], macs, chal2, false); // tag false.
	owf_constraints_prover_all_branches(&qs, pk_ring);

	uint8_t qs_check[QUICKSILVER_CHECK_BYTES];


	uint8_t* qs_proof = correction + RING_WITNESS_BITS / 8;
	uint8_t* qs_proof_quad = qs_proof + QUICKSILVER_PROOF_BYTES;
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	uint8_t* qs_proof_cubic = qs_proof_quad + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	uint8_t* qs_proof_quartic = qs_proof_cubic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	uint8_t* qs_proof_quintic = qs_proof_quartic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	quicksilver_prove_or(&qs, RING_WITNESS_BITS,
						 qs_proof_quad,
						 qs_proof, qs_check);
	#elif (FAEST_RING_HOTVECTOR_DIM == 2)
	quicksilver_prove_or(&qs, RING_WITNESS_BITS,
						 qs_proof_cubic, qs_proof_quad,
						 qs_proof, qs_check);
	#elif (FAEST_RING_HOTVECTOR_DIM == 4)
	quicksilver_prove_or(&qs, RING_WITNESS_BITS, qs_proof_quintic,
						 qs_proof_quartic, qs_proof_cubic, qs_proof_quad,
						 qs_proof, qs_check);
	#endif

	// printf("QS check prover:");
    // for (size_t i = 0; i < QUICKSILVER_CHECK_BYTES; i++) {
    //     printf("%02x", qs_check[i]);
	// }
	// printf("\n");

	free(macs);
	free(u);

	uint8_t* veccom_open_start = qs_proof + QUICKSILVER_PROOF_BYTES*FAEST_RING_PROOF_ELEMS;
	uint8_t* delta = veccom_open_start + VECTOR_COM_OPEN_SIZE;

#if COUNTER_BYTES == 0
	hash_init(&hasher);
	hash_update(&hasher, &chal2, sizeof(chal2));
	// hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	// hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	hash_update(&hasher, qs_proof_quad, QUICKSILVER_PROOF_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hash_update(&hasher, qs_proof_cubic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hash_update(&hasher, qs_proof_quartic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hash_update(&hasher, qs_proof_quintic, QUICKSILVER_PROOF_BYTES);
	#endif
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, delta, sizeof(block_secpar));

	uint8_t delta_bytes[SECURITY_PARAM];
	for (size_t i = 0; i < SECURITY_PARAM; ++i)
		delta_bytes[i] = expand_bit_to_byte(delta[i / 8], i % 8);
	vector_open(forest, hashed_leaves, delta_bytes, veccom_open_start);
	bool open_success = true;

#else
	uint32_t counter = 0;
	size_t hash_prefix_size = sizeof(chal2) + FAEST_RING_PROOF_ELEMS*QUICKSILVER_PROOF_BYTES + QUICKSILVER_CHECK_BYTES;
	unsigned char hash_prefix[hash_prefix_size];
	memcpy(hash_prefix, &chal2, sizeof(chal2));

	// memcpy(hash_prefix + sizeof(chal2), qs_proof, QUICKSILVER_PROOF_BYTES);
	// memcpy(hash_prefix + sizeof(chal2) + QUICKSILVER_PROOF_BYTES, qs_check, QUICKSILVER_CHECK_BYTES);

	memcpy(hash_prefix + sizeof(chal2), qs_check, QUICKSILVER_CHECK_BYTES);
	memcpy(hash_prefix + sizeof(chal2) + QUICKSILVER_CHECK_BYTES, qs_proof, QUICKSILVER_PROOF_BYTES);
	memcpy(hash_prefix + sizeof(chal2) + 2*QUICKSILVER_PROOF_BYTES, qs_proof_quad, QUICKSILVER_PROOF_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	memcpy(hash_prefix + sizeof(chal2) + 3*QUICKSILVER_PROOF_BYTES, qs_proof_cubic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	memcpy(hash_prefix + sizeof(chal2) + 4*QUICKSILVER_PROOF_BYTES, qs_proof_quartic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	memcpy(hash_prefix + sizeof(chal2) + 5*QUICKSILVER_PROOF_BYTES, qs_proof_quintic, QUICKSILVER_PROOF_BYTES);
	#endif

	bool open_success = force_vector_open(forest, hashed_leaves, delta, veccom_open_start, hash_prefix, hash_prefix_size, &counter);
#endif

	// printf("Delta prover:");
    // for (size_t i = 0; i < sizeof(block_secpar); i++) {
    //     printf("%02x", delta[i]);
	// }
	// printf("\n");

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

	// assert(counter_dst + COUNTER_BYTES == signature + FAEST_SIGNATURE_BYTES);
	assert(counter_dst + COUNTER_BYTES == signature + FAEST_RING_SIGNATURE_BYTES);

	return true;
}

bool faest_ring_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, secret_key* sk, const public_key_ring* pk_ring,
	const uint8_t* random_seed, size_t random_seed_len)
{
	// secret_key sk;
	// uint8_t pk_packed[FAEST_PUBLIC_KEY_BYTES];
	// if (!faest_unpack_sk_and_get_pubkey(pk_packed, sk_packed, &sk))
	// 	return false;

	uint64_t attempt_num = 0;
	do
	{
		// if (faest_sign_attempt(signature, msg, msg_len, &sk, &pk_packed[0],
		// 	                   random_seed, random_seed_len, attempt_num))
		if (faest_ring_sign_attempt(signature, msg, msg_len, sk, pk_ring, random_seed, random_seed_len, attempt_num))
		{
			faest_free_secret_key(sk);
			return true;
		}
	} while (++attempt_num != 0);

	faest_free_secret_key(sk);
	return false;
}

// bool faest_ring_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
//                   const uint8_t* pk_packed)
bool faest_ring_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  	   const public_key_ring* pk_ring)
{
    uint8_t* pk_ring_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	faest_pack_pk_ring(pk_ring_packed, pk_ring);

	block128 iv;
	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_ring_packed, FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	hash_update(&hasher, msg, msg_len);
	hash_update_byte(&hasher, 1);
	hash_final(&hasher, &mu, sizeof(mu));

	const uint8_t* vole_check_proof = signature + VOLE_RING_COMMIT_SIZE;
	const uint8_t* correction = vole_check_proof + VOLE_CHECK_PROOF_BYTES;
	const uint8_t* qs_proof = correction + RING_WITNESS_BITS / 8;
	const uint8_t* qs_proof_quad = qs_proof + QUICKSILVER_PROOF_BYTES;
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	const uint8_t* qs_proof_cubic = qs_proof_quad + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	const uint8_t* qs_proof_quartic = qs_proof_cubic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	const uint8_t* qs_proof_quintic = qs_proof_quartic + QUICKSILVER_PROOF_BYTES;
	#endif
	const uint8_t* veccom_open_start = qs_proof + QUICKSILVER_PROOF_BYTES*FAEST_RING_PROOF_ELEMS;
	const uint8_t* delta = veccom_open_start + VECTOR_COM_OPEN_SIZE;
	const uint8_t* iv_ptr = delta + sizeof(block_secpar);

#if COUNTER_BYTES > 0
	const uint8_t* counter = iv_ptr + sizeof(iv);
#endif

	uint8_t delta_bytes[SECURITY_PARAM];
	for (size_t i = 0; i < SECURITY_PARAM; ++i)
		delta_bytes[i] = expand_bit_to_byte(delta[i / 8], i % 8);

	vole_block* q =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * VOLE_RING_COL_BLOCKS * sizeof(vole_block));
	uint8_t vole_commit_check[VOLE_COMMIT_CHECK_SIZE];

	memcpy(&iv, iv_ptr, sizeof(iv));
	bool reconstruct_success =  vole_reconstruct_for_ring(iv, q, delta_bytes, signature, veccom_open_start, vole_commit_check);
	if (reconstruct_success == 0){
		free(q);
		printf("Reconstruction failed\n");
		return 0;
	}

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, vole_commit_check, VOLE_COMMIT_CHECK_SIZE);
	hash_update(&hasher, signature, VOLE_RING_COMMIT_SIZE);
	hash_update(&hasher, &iv, sizeof(iv));
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t vole_check_check[VOLE_CHECK_CHECK_BYTES];
	vole_check_receiver(q, delta_bytes, chal1, vole_check_proof, vole_check_check, QUICKSILVER_RING_ROWS, VOLE_RING_COL_BLOCKS);

	uint8_t vole_check_proof_test[VOLE_CHECK_PROOF_BYTES];
	uint8_t vole_check_check_test[VOLE_CHECK_CHECK_BYTES];
	memcpy(&vole_check_proof_test, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	memcpy(&vole_check_check_test, vole_check_check, VOLE_CHECK_CHECK_BYTES);

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &chal1, sizeof(chal1));
	hash_update(&hasher, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	hash_update(&hasher, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	hash_update(&hasher, correction, RING_WITNESS_BITS / 8);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	vole_block correction_blocks[RING_WITNESS_BLOCKS];
	memcpy(&correction_blocks, correction, RING_WITNESS_BITS / 8);
	memset(((uint8_t*) &correction_blocks) + RING_WITNESS_BITS / 8, 0,
	       sizeof(correction_blocks) - RING_WITNESS_BITS / 8);
	vole_receiver_apply_correction(RING_WITNESS_BLOCKS, NONZERO_BITS_IN_CHALLENGE_3, correction_blocks, q, delta_bytes, VOLE_RING_COL_BLOCKS);

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), VOLE_RING_ROWS_PADDED * sizeof(block_secpar));
	transpose_secpar(q, macs, VOLE_RING_COL_STRIDE, QUICKSILVER_RING_ROWS_PADDED);
	free(q);

	block_secpar delta_block;
	memcpy(&delta_block, delta, sizeof(delta_block));

	quicksilver_state qs;
	quicksilver_init_or_verifier(&qs, macs, delta_block, chal2, false); // tag false.
	owf_constraints_verifier_all_branches(&qs, pk_ring);

	uint8_t qs_check[QUICKSILVER_CHECK_BYTES];
	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	quicksilver_verify_or(&qs, RING_WITNESS_BITS, qs_proof_quad, qs_proof, qs_check);
	#elif  (FAEST_RING_HOTVECTOR_DIM == 2)
	quicksilver_verify_or(&qs, RING_WITNESS_BITS, qs_proof_cubic, qs_proof_quad, qs_proof, qs_check);
	#elif  (FAEST_RING_HOTVECTOR_DIM == 4)
	quicksilver_verify_or(&qs, RING_WITNESS_BITS, qs_proof_quintic, qs_proof_quartic, qs_proof_cubic, qs_proof_quad, qs_proof, qs_check);
	#endif
	free(macs);

	block_secpar delta_check;
	hash_init(&hasher);
	hash_update(&hasher, &chal2, sizeof(chal2));
	hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	hash_update(&hasher, qs_proof_quad, QUICKSILVER_PROOF_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hash_update(&hasher, qs_proof_cubic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hash_update(&hasher, qs_proof_quartic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hash_update(&hasher, qs_proof_quintic, QUICKSILVER_PROOF_BYTES);
	#endif

#if COUNTER_BYTES > 0
	hash_update(&hasher, counter, COUNTER_BYTES);
#endif
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &delta_check, sizeof(delta_check));

	return memcmp(delta, &delta_check, sizeof(delta_check)) == 0;
}

#if defined(OWF_AES_CTR)
static bool faest_cbc_tagged_ring_sign_attempt(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, const secret_key* sk,
	const public_key_ring* pk_ring, const cbc_tag* tag, public_key* pk_tag0, public_key* pk_tag1,
	const uint8_t* random_seed, size_t random_seed_len, uint64_t attempt_num)
{
// static bool faest_ring_sign_attempt(
// 	uint8_t* signature, const uint8_t* msg, size_t msg_len,
// 	const secret_key* sk, const uint8_t* pk_packed,
// 	const uint8_t* random_seed, size_t random_seed_len, uint64_t attempt_num)
// {
    uint8_t* pk_ring_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	faest_pack_pk_ring(pk_ring_packed, pk_ring); // TODO - EM mode.

	// uint8_t* pk_tag0_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES);
	// uint8_t* pk_tag1_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES);
	// faest_pack_public_key(pk_tag0_packed, pk_tag0);
	// faest_pack_public_key(pk_tag1_packed, pk_tag1);

	uint8_t* cbc_tag_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), OWF_BLOCK_SIZE * (CBC_TAGGED_RING_TAG_OWF_NUM + 1));
	faest_pack_cbc_tag(cbc_tag_packed, tag, CBC_TAGGED_RING_TAG_OWF_NUM);

	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_ring_packed, FAEST_RING_SIZE * FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, cbc_tag_packed,  OWF_BLOCK_SIZE * (CBC_TAGGED_RING_TAG_OWF_NUM + 1));
	// hash_update(&hasher, pk_tag0_packed,  FAEST_PUBLIC_KEY_BYTES);
	// hash_update(&hasher, pk_tag1_packed,  FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, msg, msg_len);
	hash_update_byte(&hasher, 1);
	hash_final(&hasher, &mu, sizeof(mu));

	// PARAMS.
	// TAGGED_RING_WITNESS_BITS
	size_t param_witness_bits = TAGGED_RING_WITNESS_BITS;
	// TAGGED_RING_WITNESS_BLOCKS
	size_t param_witness_blocks = TAGGED_RING_WITNESS_BLOCKS;
	// VOLE_TAGGED_RING_COMMIT_SIZE
	size_t param_vole_commit_size = VOLE_TAGGED_RING_COMMIT_SIZE;
	// VOLE_TAGGED_RING_COL_BLOCKS
	size_t param_vole_col_blocks = VOLE_TAGGED_RING_COL_BLOCKS;
	// VOLE_TAGGED_RING_COL_STRIDE
	size_t param_vole_col_stride = VOLE_TAGGED_RING_COL_STRIDE;
	// VOLE_TAGGED_RING_ROWS_PADDED
	// size_t param_vole_rows_padded = VOLE_TAGGED_RING_ROWS_PADDED;
	// QUICKSILVER_TAGGED_RING_ROWS
	size_t param_qs_rows =	QUICKSILVER_TAGGED_RING_ROWS;
	// QUICKSILVER_TAGGED_RING_ROWS_PADDED (static assert)
	// FAEST_TAGGED_RING_SIGNATURE_BYTES  (static assert)

	// vole_commit
	// Witness
	// Prover
	// Verifier

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
		aligned_alloc(alignof(vole_block), param_vole_col_blocks * sizeof(vole_block));
	vole_block* v =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * param_vole_col_blocks * sizeof(vole_block));
	uint8_t vole_commit_check[VOLE_COMMIT_CHECK_SIZE];

	// vole_commit_for_cbc_tagged_ring(seed, iv, forest, hashed_leaves, u, v, signature, vole_commit_check);
	vole_commit_for_tagged_ring(seed, iv, forest, hashed_leaves, u, v, signature, vole_commit_check);

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, vole_commit_check, VOLE_COMMIT_CHECK_SIZE);
	hash_update(&hasher, signature, param_vole_commit_size);
	hash_update(&hasher, &iv, sizeof(iv));
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t* vole_check_proof = signature + param_vole_commit_size;

	uint8_t vole_check_check[VOLE_CHECK_CHECK_BYTES];
	vole_check_sender(u, v, chal1, vole_check_proof, vole_check_check, param_qs_rows, param_vole_col_blocks);

	printf("Prover chall 1:");
    for (size_t i = 0; i < VOLE_CHECK_CHALLENGE_BYTES; i++) {
        printf("%02x", chal1[i]);
	}
	printf("\n");

	uint8_t vole_check_proof_test[VOLE_CHECK_PROOF_BYTES];
	uint8_t vole_check_check_test[VOLE_CHECK_CHECK_BYTES];
	memcpy(&vole_check_proof_test, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	memcpy(&vole_check_check_test, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	printf("Prover check proof:");
    for (size_t i = 0; i < VOLE_CHECK_PROOF_BYTES; i++) {
        printf("%02x", vole_check_proof_test[i]);
	}
	printf("\n");
	printf("Prover check check:");
    for (size_t i = 0; i < VOLE_CHECK_CHECK_BYTES; i++) {
        printf("%02x", vole_check_check_test[i]);
	}
	printf("\n");

	uint8_t* correction = vole_check_proof + VOLE_CHECK_PROOF_BYTES;
	size_t remainder = (param_witness_bits / 8) % (16 * VOLE_BLOCK);
	for (size_t i = 0; i < param_witness_blocks - (remainder != 0); ++i)
	{
		vole_block correction_i = vole_block_xor(u[i], sk->tagged_ring_witness[i]);
		memcpy(correction + i * sizeof(vole_block), &correction_i, sizeof(vole_block));
	}
	if (remainder)
	{
		vole_block correction_i = vole_block_xor(u[param_witness_blocks - 1], sk->tagged_ring_witness[param_witness_blocks - 1]);
		memcpy(correction + (param_witness_blocks - 1) * sizeof(vole_block), &correction_i, remainder);
	}

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, chal1, sizeof(chal1));
    hash_update(&hasher, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
    hash_update(&hasher, vole_check_check, VOLE_CHECK_CHECK_BYTES);
    hash_update(&hasher, correction, param_witness_bits / 8);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	printf("Prover chall 2:");
    for (size_t i = 0; i < QUICKSILVER_CHALLENGE_BYTES; i++) {
        printf("%02x", chal2[i]);
	}
	printf("\n");

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), QUICKSILVER_TAGGED_RING_ROWS_PADDED * sizeof(block_secpar));

	memcpy(&u[0], &sk->tagged_ring_witness[0], param_witness_bits / 8);

	static_assert(QUICKSILVER_TAGGED_RING_ROWS_PADDED % TRANSPOSE_BITS_ROWS == 0, "");
	transpose_secpar(v, macs, param_vole_col_stride, QUICKSILVER_TAGGED_RING_ROWS_PADDED);
	free(v);

	quicksilver_state qs;
	quicksilver_init_or_prover(&qs, (uint8_t*) &u[0], macs, chal2, true); // tag flag true.
	owf_constraints_prover_all_branches_and_tag(&qs, pk_ring, pk_tag0, pk_tag1);

	uint8_t qs_check[QUICKSILVER_CHECK_BYTES];

	uint8_t* qs_proof = correction + param_witness_bits / 8;
	uint8_t* qs_proof_quad = qs_proof + QUICKSILVER_PROOF_BYTES;
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	uint8_t* qs_proof_cubic = qs_proof_quad + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	uint8_t* qs_proof_quartic = qs_proof_cubic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	uint8_t* qs_proof_quintic = qs_proof_quartic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	quicksilver_prove_or(&qs, param_witness_bits,
						 qs_proof_quad,
						 qs_proof, qs_check);
	#elif (FAEST_RING_HOTVECTOR_DIM == 2)
	quicksilver_prove_or(&qs, param_witness_bits,
						 qs_proof_cubic, qs_proof_quad,
						 qs_proof, qs_check);
	#elif (FAEST_RING_HOTVECTOR_DIM == 4)
	quicksilver_prove_or(&qs, param_witness_bits, qs_proof_quintic,
						 qs_proof_quartic, qs_proof_cubic, qs_proof_quad,
						 qs_proof, qs_check);
	#endif
	free(macs);
	free(u);

	printf("QS check prover: ");
    for (size_t i = 0; i < QUICKSILVER_CHECK_BYTES; i++) {
        printf("%02x", qs_check[i]);
	}
	printf("\n");


	uint8_t* veccom_open_start = qs_proof + QUICKSILVER_PROOF_BYTES*FAEST_RING_PROOF_ELEMS;
	uint8_t* delta = veccom_open_start + VECTOR_COM_OPEN_SIZE;

#if COUNTER_BYTES == 0
	hash_init(&hasher);
	hash_update(&hasher, &chal2, sizeof(chal2));
	// hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	// hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	hash_update(&hasher, qs_proof_quad, QUICKSILVER_PROOF_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hash_update(&hasher, qs_proof_cubic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hash_update(&hasher, qs_proof_quartic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hash_update(&hasher, qs_proof_quintic, QUICKSILVER_PROOF_BYTES);
	#endif
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, delta, sizeof(block_secpar));

	uint8_t delta_bytes[SECURITY_PARAM];
	for (size_t i = 0; i < SECURITY_PARAM; ++i)
		delta_bytes[i] = expand_bit_to_byte(delta[i / 8], i % 8);
	vector_open(forest, hashed_leaves, delta_bytes, veccom_open_start);
	bool open_success = true;

#else
	uint32_t counter = 0;
	size_t hash_prefix_size = sizeof(chal2) + QUICKSILVER_CHECK_BYTES + FAEST_RING_PROOF_ELEMS*QUICKSILVER_PROOF_BYTES;
	unsigned char hash_prefix[hash_prefix_size];
	memcpy(hash_prefix, &chal2, sizeof(chal2));
	memcpy(hash_prefix + sizeof(chal2), qs_check, QUICKSILVER_CHECK_BYTES);
	memcpy(hash_prefix + sizeof(chal2) + QUICKSILVER_CHECK_BYTES, qs_proof, QUICKSILVER_PROOF_BYTES);
	memcpy(hash_prefix + sizeof(chal2) + 2*QUICKSILVER_PROOF_BYTES, qs_proof_quad, QUICKSILVER_CHECK_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	memcpy(hash_prefix + sizeof(chal2) + 3*QUICKSILVER_PROOF_BYTES, qs_proof_cubic, QUICKSILVER_CHECK_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	memcpy(hash_prefix + sizeof(chal2) + 4*QUICKSILVER_PROOF_BYTES, qs_proof_quartic, QUICKSILVER_CHECK_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	memcpy(hash_prefix + sizeof(chal2) + 5*QUICKSILVER_PROOF_BYTES, qs_proof_quintic, QUICKSILVER_CHECK_BYTES);
	#endif
	bool open_success = force_vector_open(forest, hashed_leaves, delta, veccom_open_start, hash_prefix, hash_prefix_size, &counter);
#endif

	printf("Delta prover:");
	uint8_t delta_test[sizeof(block_secpar)];
	memcpy(&delta_test, delta, sizeof(block_secpar));
    for (size_t i = 0; i < sizeof(block_secpar); i++) {
        printf("%02x", delta_test[i]);
	}
	printf("\n");

	printf("Prover QS check: ");
    for (size_t i = sizeof(chal2); i < sizeof(chal2)+QUICKSILVER_CHECK_BYTES; i++) {
        printf("%02x", hash_prefix[i]);
	}
	printf("\n");

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

	assert(counter_dst + COUNTER_BYTES == signature + FAEST_TAGGED_RING_SIGNATURE_BYTES);

	return true;
}
#endif


static bool faest_tagged_ring_sign_attempt(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, const secret_key* sk,
	const public_key_ring* pk_ring, public_key* pk_tag0, public_key* pk_tag1,
	const uint8_t* random_seed, size_t random_seed_len, uint64_t attempt_num)
{
// static bool faest_ring_sign_attempt(
// 	uint8_t* signature, const uint8_t* msg, size_t msg_len,
// 	const secret_key* sk, const uint8_t* pk_packed,
// 	const uint8_t* random_seed, size_t random_seed_len, uint64_t attempt_num)
// {
    uint8_t* pk_ring_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	faest_pack_pk_ring(pk_ring_packed, pk_ring); // TODO - EM mode.
	uint8_t* pk_tag0_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES);
	uint8_t* pk_tag1_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES);
	faest_pack_public_key(pk_tag0_packed, pk_tag0);
	faest_pack_public_key(pk_tag1_packed, pk_tag1);

	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_ring_packed, FAEST_RING_SIZE * FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, pk_tag0_packed,  FAEST_PUBLIC_KEY_BYTES); // JC: Add to verifier.
	hash_update(&hasher, pk_tag1_packed,  FAEST_PUBLIC_KEY_BYTES); // JC: Add to verifier.
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
		aligned_alloc(alignof(vole_block), VOLE_TAGGED_RING_COL_BLOCKS * sizeof(vole_block));
	vole_block* v =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * VOLE_TAGGED_RING_COL_BLOCKS * sizeof(vole_block));
	uint8_t vole_commit_check[VOLE_COMMIT_CHECK_SIZE];

	vole_commit_for_tagged_ring(seed, iv, forest, hashed_leaves, u, v, signature, vole_commit_check);

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, vole_commit_check, VOLE_COMMIT_CHECK_SIZE);
	hash_update(&hasher, signature, VOLE_TAGGED_RING_COMMIT_SIZE);
	hash_update(&hasher, &iv, sizeof(iv));
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t* vole_check_proof = signature + VOLE_TAGGED_RING_COMMIT_SIZE;

	uint8_t vole_check_check[VOLE_CHECK_CHECK_BYTES];
	vole_check_sender(u, v, chal1, vole_check_proof, vole_check_check, QUICKSILVER_TAGGED_RING_ROWS, VOLE_TAGGED_RING_COL_BLOCKS);

	printf("Prover chall 1:");
    for (size_t i = 0; i < VOLE_CHECK_CHALLENGE_BYTES; i++) {
        printf("%02x", chal1[i]);
	}
	printf("\n");

	uint8_t vole_check_proof_test[VOLE_CHECK_PROOF_BYTES];
	uint8_t vole_check_check_test[VOLE_CHECK_CHECK_BYTES];
	memcpy(&vole_check_proof_test, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	memcpy(&vole_check_check_test, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	printf("Prover check proof:");
    for (size_t i = 0; i < VOLE_CHECK_PROOF_BYTES; i++) {
        printf("%02x", vole_check_proof_test[i]);
	}
	printf("\n");
	printf("Prover check check:");
    for (size_t i = 0; i < VOLE_CHECK_CHECK_BYTES; i++) {
        printf("%02x", vole_check_check_test[i]);
	}
	printf("\n");

	uint8_t* correction = vole_check_proof + VOLE_CHECK_PROOF_BYTES;
	size_t remainder = (TAGGED_RING_WITNESS_BITS / 8) % (16 * VOLE_BLOCK);
	for (size_t i = 0; i < TAGGED_RING_WITNESS_BLOCKS - (remainder != 0); ++i)
	{
		vole_block correction_i = vole_block_xor(u[i], sk->tagged_ring_witness[i]);
		memcpy(correction + i * sizeof(vole_block), &correction_i, sizeof(vole_block));
	}
	if (remainder)
	{
		vole_block correction_i = vole_block_xor(u[TAGGED_RING_WITNESS_BLOCKS - 1], sk->tagged_ring_witness[TAGGED_RING_WITNESS_BLOCKS - 1]);
		memcpy(correction + (TAGGED_RING_WITNESS_BLOCKS - 1) * sizeof(vole_block), &correction_i, remainder);
	}

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, chal1, sizeof(chal1));
    hash_update(&hasher, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
    hash_update(&hasher, vole_check_check, VOLE_CHECK_CHECK_BYTES);
    hash_update(&hasher, correction, TAGGED_RING_WITNESS_BITS / 8);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	printf("Prover chall 2:");
    for (size_t i = 0; i < QUICKSILVER_CHALLENGE_BYTES; i++) {
        printf("%02x", chal2[i]);
	}
	printf("\n");

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), QUICKSILVER_TAGGED_RING_ROWS_PADDED * sizeof(block_secpar));

	memcpy(&u[0], &sk->tagged_ring_witness[0], TAGGED_RING_WITNESS_BITS / 8);

	static_assert(QUICKSILVER_TAGGED_RING_ROWS_PADDED % TRANSPOSE_BITS_ROWS == 0, "");
	transpose_secpar(v, macs, VOLE_TAGGED_RING_COL_STRIDE, QUICKSILVER_TAGGED_RING_ROWS_PADDED);
	free(v);

	quicksilver_state qs;
	quicksilver_init_or_prover(&qs, (uint8_t*) &u[0], macs, chal2, true); // tag flag true.
	owf_constraints_prover_all_branches_and_tag(&qs, pk_ring, pk_tag0, pk_tag1);

	uint8_t qs_check[QUICKSILVER_CHECK_BYTES];

	uint8_t* qs_proof = correction + TAGGED_RING_WITNESS_BITS / 8;
	uint8_t* qs_proof_quad = qs_proof + QUICKSILVER_PROOF_BYTES;
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	uint8_t* qs_proof_cubic = qs_proof_quad + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	uint8_t* qs_proof_quartic = qs_proof_cubic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	uint8_t* qs_proof_quintic = qs_proof_quartic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	quicksilver_prove_or(&qs, TAGGED_RING_WITNESS_BITS,
						 qs_proof_quad,
						 qs_proof, qs_check);
	#elif (FAEST_RING_HOTVECTOR_DIM == 2)
	quicksilver_prove_or(&qs, TAGGED_RING_WITNESS_BITS,
						 qs_proof_cubic, qs_proof_quad,
						 qs_proof, qs_check);
	#elif (FAEST_RING_HOTVECTOR_DIM == 4)
	quicksilver_prove_or(&qs, TAGGED_RING_WITNESS_BITS, qs_proof_quintic,
						 qs_proof_quartic, qs_proof_cubic, qs_proof_quad,
						 qs_proof, qs_check);
	#endif
	free(macs);
	free(u);

	printf("QS check prover: ");
    for (size_t i = 0; i < QUICKSILVER_CHECK_BYTES; i++) {
        printf("%02x", qs_check[i]);
	}
	printf("\n");


	uint8_t* veccom_open_start = qs_proof + QUICKSILVER_PROOF_BYTES*FAEST_RING_PROOF_ELEMS;
	uint8_t* delta = veccom_open_start + VECTOR_COM_OPEN_SIZE;

#if COUNTER_BYTES == 0
	hash_init(&hasher);
	hash_update(&hasher, &chal2, sizeof(chal2));
	// hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	// hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	hash_update(&hasher, qs_proof_quad, QUICKSILVER_PROOF_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hash_update(&hasher, qs_proof_cubic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hash_update(&hasher, qs_proof_quartic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hash_update(&hasher, qs_proof_quintic, QUICKSILVER_PROOF_BYTES);
	#endif
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, delta, sizeof(block_secpar));

	uint8_t delta_bytes[SECURITY_PARAM];
	for (size_t i = 0; i < SECURITY_PARAM; ++i)
		delta_bytes[i] = expand_bit_to_byte(delta[i / 8], i % 8);
	vector_open(forest, hashed_leaves, delta_bytes, veccom_open_start);
	bool open_success = true;

#else
	uint32_t counter = 0;
	size_t hash_prefix_size = sizeof(chal2) + QUICKSILVER_CHECK_BYTES + FAEST_RING_PROOF_ELEMS*QUICKSILVER_PROOF_BYTES;
	unsigned char hash_prefix[hash_prefix_size];
	memcpy(hash_prefix, &chal2, sizeof(chal2));
	memcpy(hash_prefix + sizeof(chal2), qs_check, QUICKSILVER_CHECK_BYTES);
	memcpy(hash_prefix + sizeof(chal2) + QUICKSILVER_CHECK_BYTES, qs_proof, QUICKSILVER_PROOF_BYTES);
	memcpy(hash_prefix + sizeof(chal2) + 2*QUICKSILVER_PROOF_BYTES, qs_proof_quad, QUICKSILVER_CHECK_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	memcpy(hash_prefix + sizeof(chal2) + 3*QUICKSILVER_PROOF_BYTES, qs_proof_cubic, QUICKSILVER_CHECK_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	memcpy(hash_prefix + sizeof(chal2) + 4*QUICKSILVER_PROOF_BYTES, qs_proof_quartic, QUICKSILVER_CHECK_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	memcpy(hash_prefix + sizeof(chal2) + 5*QUICKSILVER_PROOF_BYTES, qs_proof_quintic, QUICKSILVER_CHECK_BYTES);
	#endif
	bool open_success = force_vector_open(forest, hashed_leaves, delta, veccom_open_start, hash_prefix, hash_prefix_size, &counter);
#endif

	printf("Delta prover:");
	uint8_t delta_test[sizeof(block_secpar)];
	memcpy(&delta_test, delta, sizeof(block_secpar));
    for (size_t i = 0; i < sizeof(block_secpar); i++) {
        printf("%02x", delta_test[i]);
	}
	printf("\n");

	printf("Prover QS check: ");
    for (size_t i = sizeof(chal2); i < sizeof(chal2)+QUICKSILVER_CHECK_BYTES; i++) {
        printf("%02x", hash_prefix[i]);
	}
	printf("\n");

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

	assert(counter_dst + COUNTER_BYTES == signature + FAEST_TAGGED_RING_SIGNATURE_BYTES);

	return true;
}

#if defined(OWF_AES_CTR)
bool faest_cbc_tagged_ring_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, secret_key* sk, const public_key_ring* pk_ring,
	const cbc_tag* tag, public_key* pk_tag0, public_key* pk_tag1, const uint8_t* random_seed, size_t random_seed_len)
{
	uint64_t attempt_num = 0;
	do
	{
		if (faest_cbc_tagged_ring_sign_attempt(signature, msg, msg_len, sk, pk_ring, tag, pk_tag0, pk_tag1, random_seed, random_seed_len, attempt_num))
		{
			faest_free_secret_key(sk);
			return true;
		}
	} while (++attempt_num != 0);

	faest_free_secret_key(sk);
	return false;
}
#endif

bool faest_tagged_ring_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, secret_key* sk, const public_key_ring* pk_ring,
 	public_key* pk_tag0, public_key* pk_tag1, const uint8_t* random_seed, size_t random_seed_len)
{
	uint64_t attempt_num = 0;
	do
	{
		if (faest_tagged_ring_sign_attempt(signature, msg, msg_len, sk, pk_ring, pk_tag0, pk_tag1, random_seed, random_seed_len, attempt_num))
		{
			faest_free_secret_key(sk);
			return true;
		}
	} while (++attempt_num != 0);

	faest_free_secret_key(sk);
	return false;
}

#if defined(OWF_AES_CTR)

bool faest_cbc_tagged_ring_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  	   const public_key_ring* pk_ring, const cbc_tag* tag, public_key* pk_tag0, public_key* pk_tag1)
{
    uint8_t* pk_ring_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	faest_pack_pk_ring(pk_ring_packed, pk_ring);
	// uint8_t* pk_tag0_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES);
	// uint8_t* pk_tag1_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES);
	// faest_pack_public_key(pk_tag0_packed, pk_tag0);
	// faest_pack_public_key(pk_tag1_packed, pk_tag1);

	uint8_t* cbc_tag_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), OWF_BLOCK_SIZE * (CBC_TAGGED_RING_TAG_OWF_NUM + 1));
	faest_pack_cbc_tag(cbc_tag_packed, tag, CBC_TAGGED_RING_TAG_OWF_NUM);

	block128 iv;
	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_ring_packed, FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	hash_update(&hasher, cbc_tag_packed,  OWF_BLOCK_SIZE * (CBC_TAGGED_RING_TAG_OWF_NUM + 1));
	// hash_update(&hasher, pk_tag0_packed,  FAEST_PUBLIC_KEY_BYTES);
	// hash_update(&hasher, pk_tag1_packed,  FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, msg, msg_len);
	hash_update_byte(&hasher, 1);
	hash_final(&hasher, &mu, sizeof(mu));

	// PARAMS.
	// TAGGED_RING_WITNESS_BITS
	size_t param_witness_bits = TAGGED_RING_WITNESS_BITS;
	// TAGGED_RING_WITNESS_BLOCKS
	size_t param_witness_blocks = TAGGED_RING_WITNESS_BLOCKS;
	// VOLE_TAGGED_RING_COMMIT_SIZE
	size_t param_vole_commit_size = VOLE_TAGGED_RING_COMMIT_SIZE;
	// VOLE_TAGGED_RING_COL_BLOCKS
	size_t param_vole_col_blocks = VOLE_TAGGED_RING_COL_BLOCKS;
	// VOLE_TAGGED_RING_COL_STRIDE
	size_t param_vole_col_stride = VOLE_TAGGED_RING_COL_STRIDE;
	// VOLE_TAGGED_RING_ROWS_PADDED
	size_t param_vole_rows_padded = VOLE_TAGGED_RING_ROWS_PADDED;
	// QUICKSILVER_TAGGED_RING_ROWS
	size_t param_qs_rows =	QUICKSILVER_TAGGED_RING_ROWS;
	// QUICKSILVER_TAGGED_RING_ROWS_PADDED (static assert)

	// vole_reconstruct
	// Prover
	// Verifier

	const uint8_t* vole_check_proof = signature + param_vole_commit_size;
	const uint8_t* correction = vole_check_proof + VOLE_CHECK_PROOF_BYTES;
	const uint8_t* qs_proof = correction + param_witness_bits / 8;
	const uint8_t* qs_proof_quad = qs_proof + QUICKSILVER_PROOF_BYTES;
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	const uint8_t* qs_proof_cubic = qs_proof_quad + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	const uint8_t* qs_proof_quartic = qs_proof_cubic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	const uint8_t* qs_proof_quintic = qs_proof_quartic + QUICKSILVER_PROOF_BYTES;
	#endif
	const uint8_t* veccom_open_start = qs_proof + QUICKSILVER_PROOF_BYTES*FAEST_RING_PROOF_ELEMS;
	const uint8_t* delta = veccom_open_start + VECTOR_COM_OPEN_SIZE;
	const uint8_t* iv_ptr = delta + sizeof(block_secpar);

	printf("Delta verifier:");
	uint8_t delta_test[SECURITY_PARAM / 8];
	memcpy(&delta_test, delta, sizeof(block_secpar));
    for (size_t i = 0; i < sizeof(block_secpar); i++) {
        printf("%02x", delta_test[i]);
	}
	printf("\n");

#if COUNTER_BYTES > 0
	const uint8_t* counter = iv_ptr + sizeof(iv);
#endif

	uint8_t delta_bytes[SECURITY_PARAM];
	for (size_t i = 0; i < SECURITY_PARAM; ++i)
		delta_bytes[i] = expand_bit_to_byte(delta[i / 8], i % 8);

	vole_block* q =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * param_vole_col_blocks * sizeof(vole_block));
	uint8_t vole_commit_check[VOLE_COMMIT_CHECK_SIZE];

	memcpy(&iv, iv_ptr, sizeof(iv));
	bool reconstruct_success =  vole_reconstruct_for_tagged_ring(iv, q, delta_bytes, signature, veccom_open_start, vole_commit_check);
	// bool reconstruct_success =  vole_reconstruct_for_cbc_tagged_ring(iv, q, delta_bytes, signature, veccom_open_start, vole_commit_check);
	if (reconstruct_success == 0){
		free(q);
		printf("Reconstruction failed\n");
		return 0;
	}

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, vole_commit_check, VOLE_COMMIT_CHECK_SIZE);
	hash_update(&hasher, signature, param_vole_commit_size);
	hash_update(&hasher, &iv, sizeof(iv));
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t vole_check_check[VOLE_CHECK_CHECK_BYTES];
	vole_check_receiver(q, delta_bytes, chal1, vole_check_proof, vole_check_check, param_qs_rows, param_vole_col_blocks);

	printf("Verifier chall 1:");
    for (size_t i = 0; i < VOLE_CHECK_CHALLENGE_BYTES; i++) {
        printf("%02x", chal1[i]);
	}
	printf("\n");

	uint8_t vole_check_proof_test[VOLE_CHECK_PROOF_BYTES];
	uint8_t vole_check_check_test[VOLE_CHECK_CHECK_BYTES];
	memcpy(&vole_check_proof_test, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	memcpy(&vole_check_check_test, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	printf("Verifier check proof:");
    for (size_t i = 0; i < VOLE_CHECK_PROOF_BYTES; i++) {
        printf("%02x", vole_check_proof_test[i]);
	}
	printf("\n");
	printf("Verifier check check:");
    for (size_t i = 0; i < VOLE_CHECK_CHECK_BYTES; i++) {
        printf("%02x", vole_check_check_test[i]);
	}
	printf("\n");

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &chal1, sizeof(chal1));
	hash_update(&hasher, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	hash_update(&hasher, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	hash_update(&hasher, correction, param_witness_bits / 8);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	printf("Verifier chall 2:");
    for (size_t i = 0; i < QUICKSILVER_CHALLENGE_BYTES; i++) {
        printf("%02x", chal2[i]);
	}
	printf("\n");

	vole_block correction_blocks[param_witness_blocks];
	memcpy(&correction_blocks, correction, param_witness_bits / 8);
	memset(((uint8_t*) &correction_blocks) + param_witness_bits / 8, 0,
	       sizeof(correction_blocks) - param_witness_bits / 8);
	vole_receiver_apply_correction(param_witness_blocks, NONZERO_BITS_IN_CHALLENGE_3, correction_blocks, q, delta_bytes, param_vole_col_blocks);

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), param_vole_rows_padded * sizeof(block_secpar));
	transpose_secpar(q, macs, param_vole_col_stride, QUICKSILVER_TAGGED_RING_ROWS_PADDED);
	free(q);

	block_secpar delta_block;
	memcpy(&delta_block, delta, sizeof(delta_block));

	quicksilver_state qs;
	quicksilver_init_or_verifier(&qs, macs, delta_block, chal2, true); // tag true.
	owf_constraints_verifier_all_branches_and_tag(&qs, pk_ring, pk_tag0, pk_tag1);

	uint8_t qs_check[QUICKSILVER_CHECK_BYTES];
	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	quicksilver_verify_or(&qs, param_witness_bits, qs_proof_quad, qs_proof, qs_check);
	#elif  (FAEST_RING_HOTVECTOR_DIM == 2)
	quicksilver_verify_or(&qs, param_witness_bits, qs_proof_cubic, qs_proof_quad, qs_proof, qs_check);
	#elif  (FAEST_RING_HOTVECTOR_DIM == 4)
	quicksilver_verify_or(&qs, param_witness_bits, qs_proof_quintic, qs_proof_quartic, qs_proof_cubic, qs_proof_quad, qs_proof, qs_check);
	#endif
	free(macs);

	block_secpar delta_check;
	hash_init(&hasher);
	hash_update(&hasher, &chal2, sizeof(chal2));
	hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	printf("Verifier qs check: ");
	for (size_t i = 0; i < QUICKSILVER_CHECK_BYTES; i++) {
        printf("%02x", qs_check[i]);
	}
	printf("\n");
	hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	hash_update(&hasher, qs_proof_quad, QUICKSILVER_PROOF_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hash_update(&hasher, qs_proof_cubic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hash_update(&hasher, qs_proof_quartic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hash_update(&hasher, qs_proof_quintic, QUICKSILVER_PROOF_BYTES);
	#endif

#if COUNTER_BYTES > 0
	hash_update(&hasher, counter, COUNTER_BYTES);
#endif
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &delta_check, sizeof(delta_check));

	return memcmp(delta, &delta_check, sizeof(delta_check)) == 0;
}
#endif


bool faest_tagged_ring_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  	   const public_key_ring* pk_ring, public_key* pk_tag0, public_key* pk_tag1)
{
    uint8_t* pk_ring_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	faest_pack_pk_ring(pk_ring_packed, pk_ring);
	uint8_t* pk_tag0_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES);
	uint8_t* pk_tag1_packed = (uint8_t *)aligned_alloc(alignof(uint8_t), FAEST_PUBLIC_KEY_BYTES);
	faest_pack_public_key(pk_tag0_packed, pk_tag0);
	faest_pack_public_key(pk_tag1_packed, pk_tag1);

	block128 iv;
	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_ring_packed, FAEST_PUBLIC_KEY_BYTES * FAEST_RING_SIZE);
	hash_update(&hasher, pk_tag0_packed,  FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, pk_tag1_packed,  FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, msg, msg_len);
	hash_update_byte(&hasher, 1);
	hash_final(&hasher, &mu, sizeof(mu));

	const uint8_t* vole_check_proof = signature + VOLE_TAGGED_RING_COMMIT_SIZE;
	const uint8_t* correction = vole_check_proof + VOLE_CHECK_PROOF_BYTES;
	const uint8_t* qs_proof = correction + TAGGED_RING_WITNESS_BITS / 8;
	const uint8_t* qs_proof_quad = qs_proof + QUICKSILVER_PROOF_BYTES;
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	const uint8_t* qs_proof_cubic = qs_proof_quad + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	const uint8_t* qs_proof_quartic = qs_proof_cubic + QUICKSILVER_PROOF_BYTES;
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	const uint8_t* qs_proof_quintic = qs_proof_quartic + QUICKSILVER_PROOF_BYTES;
	#endif
	const uint8_t* veccom_open_start = qs_proof + QUICKSILVER_PROOF_BYTES*FAEST_RING_PROOF_ELEMS;
	const uint8_t* delta = veccom_open_start + VECTOR_COM_OPEN_SIZE;
	const uint8_t* iv_ptr = delta + sizeof(block_secpar);

	printf("Delta verifier:");
	uint8_t delta_test[SECURITY_PARAM / 8];
	memcpy(&delta_test, delta, sizeof(block_secpar));
    for (size_t i = 0; i < sizeof(block_secpar); i++) {
        printf("%02x", delta_test[i]);
	}
	printf("\n");

#if COUNTER_BYTES > 0
	const uint8_t* counter = iv_ptr + sizeof(iv);
#endif

	uint8_t delta_bytes[SECURITY_PARAM];
	for (size_t i = 0; i < SECURITY_PARAM; ++i)
		delta_bytes[i] = expand_bit_to_byte(delta[i / 8], i % 8);

	vole_block* q =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * VOLE_TAGGED_RING_COL_BLOCKS * sizeof(vole_block));
	uint8_t vole_commit_check[VOLE_COMMIT_CHECK_SIZE];

	memcpy(&iv, iv_ptr, sizeof(iv));
	bool reconstruct_success =  vole_reconstruct_for_tagged_ring(iv, q, delta_bytes, signature, veccom_open_start, vole_commit_check);
	if (reconstruct_success == 0){
		free(q);
		printf("Reconstruction failed\n");
		return 0;
	}

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, vole_commit_check, VOLE_COMMIT_CHECK_SIZE);
	hash_update(&hasher, signature, VOLE_TAGGED_RING_COMMIT_SIZE);
	hash_update(&hasher, &iv, sizeof(iv));
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t vole_check_check[VOLE_CHECK_CHECK_BYTES];
	vole_check_receiver(q, delta_bytes, chal1, vole_check_proof, vole_check_check, QUICKSILVER_TAGGED_RING_ROWS, VOLE_TAGGED_RING_COL_BLOCKS);

	printf("Verifier chall 1:");
    for (size_t i = 0; i < VOLE_CHECK_CHALLENGE_BYTES; i++) {
        printf("%02x", chal1[i]);
	}
	printf("\n");

	uint8_t vole_check_proof_test[VOLE_CHECK_PROOF_BYTES];
	uint8_t vole_check_check_test[VOLE_CHECK_CHECK_BYTES];
	memcpy(&vole_check_proof_test, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	memcpy(&vole_check_check_test, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	printf("Verifier check proof:");
    for (size_t i = 0; i < VOLE_CHECK_PROOF_BYTES; i++) {
        printf("%02x", vole_check_proof_test[i]);
	}
	printf("\n");
	printf("Verifier check check:");
    for (size_t i = 0; i < VOLE_CHECK_CHECK_BYTES; i++) {
        printf("%02x", vole_check_check_test[i]);
	}
	printf("\n");

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &chal1, sizeof(chal1));
	hash_update(&hasher, vole_check_proof, VOLE_CHECK_PROOF_BYTES);
	hash_update(&hasher, vole_check_check, VOLE_CHECK_CHECK_BYTES);
	hash_update(&hasher, correction, TAGGED_RING_WITNESS_BITS / 8);
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	printf("Verifier chall 2:");
    for (size_t i = 0; i < QUICKSILVER_CHALLENGE_BYTES; i++) {
        printf("%02x", chal2[i]);
	}
	printf("\n");

	vole_block correction_blocks[TAGGED_RING_WITNESS_BLOCKS];
	memcpy(&correction_blocks, correction, TAGGED_RING_WITNESS_BITS / 8);
	memset(((uint8_t*) &correction_blocks) + TAGGED_RING_WITNESS_BITS / 8, 0,
	       sizeof(correction_blocks) - TAGGED_RING_WITNESS_BITS / 8);
	vole_receiver_apply_correction(TAGGED_RING_WITNESS_BLOCKS, NONZERO_BITS_IN_CHALLENGE_3, correction_blocks, q, delta_bytes, VOLE_TAGGED_RING_COL_BLOCKS);

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), VOLE_TAGGED_RING_ROWS_PADDED * sizeof(block_secpar));
	transpose_secpar(q, macs, VOLE_TAGGED_RING_COL_STRIDE, QUICKSILVER_TAGGED_RING_ROWS_PADDED);
	free(q);

	block_secpar delta_block;
	memcpy(&delta_block, delta, sizeof(delta_block));

	quicksilver_state qs;
	quicksilver_init_or_verifier(&qs, macs, delta_block, chal2, true); // tag true.
	owf_constraints_verifier_all_branches_and_tag(&qs, pk_ring, pk_tag0, pk_tag1);

	uint8_t qs_check[QUICKSILVER_CHECK_BYTES];
	#if (FAEST_RING_HOTVECTOR_DIM == 1)
	quicksilver_verify_or(&qs, TAGGED_RING_WITNESS_BITS, qs_proof_quad, qs_proof, qs_check);
	#elif  (FAEST_RING_HOTVECTOR_DIM == 2)
	quicksilver_verify_or(&qs, TAGGED_RING_WITNESS_BITS, qs_proof_cubic, qs_proof_quad, qs_proof, qs_check);
	#elif  (FAEST_RING_HOTVECTOR_DIM == 4)
	quicksilver_verify_or(&qs, TAGGED_RING_WITNESS_BITS, qs_proof_quintic, qs_proof_quartic, qs_proof_cubic, qs_proof_quad, qs_proof, qs_check);
	#endif
	free(macs);

	block_secpar delta_check;
	hash_init(&hasher);
	hash_update(&hasher, &chal2, sizeof(chal2));
	hash_update(&hasher, qs_check, QUICKSILVER_CHECK_BYTES);
	printf("Verifier qs check: ");
	for (size_t i = 0; i < QUICKSILVER_CHECK_BYTES; i++) {
        printf("%02x", qs_check[i]);
	}
	printf("\n");
	hash_update(&hasher, qs_proof, QUICKSILVER_PROOF_BYTES);
	hash_update(&hasher, qs_proof_quad, QUICKSILVER_PROOF_BYTES);
	#if (FAEST_RING_HOTVECTOR_DIM > 1)
	hash_update(&hasher, qs_proof_cubic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 2)
	hash_update(&hasher, qs_proof_quartic, QUICKSILVER_PROOF_BYTES);
	#endif
	#if (FAEST_RING_HOTVECTOR_DIM > 3)
	hash_update(&hasher, qs_proof_quintic, QUICKSILVER_PROOF_BYTES);
	#endif

#if COUNTER_BYTES > 0
	hash_update(&hasher, counter, COUNTER_BYTES);
#endif
	hash_update_byte(&hasher, 2);
	hash_final(&hasher, &delta_check, sizeof(delta_check));

	return memcmp(delta, &delta_check, sizeof(delta_check)) == 0;
}
