#ifndef OWF_PROOF_H
#define OWF_PROOF_H

#include <stdio.h>

#if defined(OWF_AES_CTR)

	// Number of applications of the round function per encryption (need OWF_ROUNDS + 1 round keys).
	#define OWF_ROUNDS AES_ROUNDS
	// Block size of the cipher
	#define OWF_BLOCK_SIZE 16
	// Number of blocks encrypted in the OWF.
	// (1 for 128 bit, 2 for 192/256 bit to compensate for the 128 bit block size)
	#define OWF_BLOCKS ((SECURITY_PARAM + 127) / 128)
	// How many constraints are used to encode the correctness of evaluating a single round.
#if defined(ALLOW_ZERO_SBOX)
	#define OWF_CONSTRAINTS_PER_ROUND (2*OWF_BLOCK_SIZE)
#else
	#define OWF_CONSTRAINTS_PER_ROUND OWF_BLOCK_SIZE
#endif

	// Spacing in bytes of the sub_words operation in the key schedule.
	#if SECURITY_PARAM == 256
	#define OWF_KEY_SCHEDULE_PERIOD 16
	#else
	#define OWF_KEY_SCHEDULE_PERIOD (SECURITY_PARAM / 8)
	#endif

	// Number of S-boxes in the key schedule.
#if defined(ALLOW_ZERO_SBOX)
	#define OWF_KEY_SCHEDULE_CONSTRAINTS \
		(8 * (((AES_ROUNDS + 1) * 16 - SECURITY_PARAM / 8 + \
			OWF_KEY_SCHEDULE_PERIOD - 1) / OWF_KEY_SCHEDULE_PERIOD))
	#define OWF_KEY_WITNESS_BITS (SECURITY_PARAM + 4 * OWF_KEY_SCHEDULE_CONSTRAINTS)
#else
	#define OWF_KEY_SCHEDULE_CONSTRAINTS \
		(4 * (((AES_ROUNDS + 1) * 16 - SECURITY_PARAM / 8 + \
			OWF_KEY_SCHEDULE_PERIOD - 1) / OWF_KEY_SCHEDULE_PERIOD))
	#define OWF_KEY_WITNESS_BITS (SECURITY_PARAM + 8 * OWF_KEY_SCHEDULE_CONSTRAINTS)
#endif

	typedef block128 owf_block;
	inline owf_block owf_block_xor(owf_block x, owf_block y) { return block128_xor(x, y); }
	inline owf_block owf_block_set_low32(uint32_t x) { return block128_set_low32(x); }
	// TODO: owf_block_set_msb(bool x) { return block128_set_msb(x); }
	inline bool owf_block_any_zeros(owf_block x) { return block128_any_zeros(x); }
	inline owf_block owf_block_activate_msb(owf_block x) { return block128_activate_msb(x); }

#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)

	#define OWF_KEY_SCHEDULE_CONSTRAINTS 0
	#define OWF_KEY_WITNESS_BITS SECURITY_PARAM
	#define OWF_BLOCK_SIZE (SECURITY_PARAM / 8)
#if defined(ALLOW_ZERO_SBOX)
	#define OWF_CONSTRAINTS_PER_ROUND (2*OWF_BLOCK_SIZE)
#else
	#define OWF_CONSTRAINTS_PER_ROUND OWF_BLOCK_SIZE
#endif
	#define OWF_BLOCKS 1

	#if SECURITY_PARAM == 128
	#define OWF_ROUNDS AES_ROUNDS
	#elif SECURITY_PARAM == 192
	#define OWF_ROUNDS RIJNDAEL192_ROUNDS
	#elif SECURITY_PARAM == 256
	#define OWF_ROUNDS RIJNDAEL256_ROUNDS
	#endif

	typedef block_secpar owf_block;
	inline owf_block owf_block_xor(owf_block x, owf_block y) { return block_secpar_xor(x, y); }
	inline owf_block owf_block_set_low32(uint32_t x) { return block_secpar_set_low32(x); }
	inline bool owf_block_any_zeros(owf_block x) { return block_secpar_any_zeros(x); }
	inline owf_block owf_block_activate_msb(owf_block x) { return block_secpar_activate_msb(x); }

#elif defined(OWF_RAIN_3)

	#define OWF_KEY_SCHEDULE_CONSTRAINTS 0
	#define OWF_KEY_WITNESS_BITS SECURITY_PARAM
	#define OWF_BLOCK_SIZE (SECURITY_PARAM / 8)
	#define OWF_CONSTRAINTS_PER_ROUND 1
	#define OWF_BLOCKS 1
	#define OWF_ROUNDS RAIN_ROUNDS

	typedef block_secpar owf_block;
	inline owf_block owf_block_xor(owf_block x, owf_block y) { return block_secpar_xor(x, y); }
	inline owf_block owf_block_set_low32(uint32_t x) { return block_secpar_set_low32(x); }
	inline bool owf_block_any_zeros(owf_block x) { return block_secpar_any_zeros(x); }

#elif defined(OWF_RAIN_4)

	#define OWF_KEY_SCHEDULE_CONSTRAINTS 0
	#define OWF_KEY_WITNESS_BITS SECURITY_PARAM
	#define OWF_BLOCK_SIZE (SECURITY_PARAM / 8)
	#define OWF_CONSTRAINTS_PER_ROUND 1
	#define OWF_BLOCKS 1
	#define OWF_ROUNDS RAIN_ROUNDS

	typedef block_secpar owf_block;
	inline owf_block owf_block_xor(owf_block x, owf_block y) { return block_secpar_xor(x, y); }
	inline owf_block owf_block_set_low32(uint32_t x) { return block_secpar_set_low32(x); }
	inline bool owf_block_any_zeros(owf_block x) { return block_secpar_any_zeros(x); }

#elif defined(OWF_MQ_2_1) || defined(OWF_MQ_2_8)

#define OWF_KEY_SCHEDULE_CONSTRAINTS 0
#define OWF_KEY_WITNESS_BITS (MQ_M*MQ_GF_BITS)
#define OWF_BLOCK_SIZE 1
#define OWF_BLOCKS 1
#define OWF_ROUNDS 1
#define OWF_CONSTRAINTS_PER_ROUND ((MQ_M * MQ_GF_BITS + SECURITY_PARAM - 1) / SECURITY_PARAM)

#else

#error "Unsupported one-way function."
#endif

#define ENC_SCHEDULE_CONSTRAINTS (OWF_BLOCKS * OWF_CONSTRAINTS_PER_ROUND * OWF_ROUNDS)
#define OWF_NUM_CONSTRAINTS (OWF_BLOCKS * OWF_CONSTRAINTS_PER_ROUND * OWF_ROUNDS + OWF_KEY_SCHEDULE_CONSTRAINTS)
#define WITNESS_BITS (8 * OWF_BLOCKS * OWF_BLOCK_SIZE * (OWF_ROUNDS - 1) + OWF_KEY_WITNESS_BITS)
#define RING_WITNESS_BITS (WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8)

// JC: Double the number of OWF for tagged ring sigs
#define TAGGED_RING_PK_OWF_NUM (2)
#define TAGGED_RING_TAG_OWF_NUM (2)
#define TAGGED_RING_TAG_OWF_NUM3 (2)

#if defined(OWF_AES_CTR)
	#if SECURITY_PARAM == 128
		#define TAGGED_RING_CBC_OWF_NUM (2)
	#elif SECURITY_PARAM == 192
		#define TAGGED_RING_CBC_OWF_NUM (3)
	#elif SECURITY_PARAM == 256
		#define TAGGED_RING_CBC_OWF_NUM (4)
	#endif
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	// TODO: Remote EM mode for CBC.
	#define TAGGED_RING_CBC_OWF_NUM (2)
#endif

#define TAGGED_RING_WITNESS_BITS ((TAGGED_RING_PK_OWF_NUM + TAGGED_RING_TAG_OWF_NUM) * (8 * OWF_BLOCKS * OWF_BLOCK_SIZE * (OWF_ROUNDS - 1)) + OWF_KEY_WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8)

#define TAGGED_RING_CBC_WITNESS_BITS ((TAGGED_RING_PK_OWF_NUM + 1) * (8 * OWF_BLOCKS * OWF_BLOCK_SIZE * (OWF_ROUNDS - 1)) + (TAGGED_RING_CBC_OWF_NUM - 1) * (8 * OWF_BLOCKS * OWF_BLOCK_SIZE * OWF_ROUNDS) + OWF_KEY_WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8)

#define TAGGED_RING_CBC_WITNESS_BITS2 ((TAGGED_RING_PK_OWF_NUM + TAGGED_RING_CBC_OWF_NUM) * (8 * OWF_BLOCKS * OWF_BLOCK_SIZE * (OWF_ROUNDS - 1)) + OWF_KEY_WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8)

#define TAGGED_RING_WITNESS_BITS3 (TAGGED_RING_PK_OWF_NUM * (8 * OWF_BLOCKS * OWF_BLOCK_SIZE * (OWF_ROUNDS - 1)) + TAGGED_RING_TAG_OWF_NUM3 * (8 * OWF_BLOCK_SIZE * (OWF_ROUNDS - 1)) + OWF_KEY_WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8)

#include "aes.h"
#include "rain.h"
#include "mq.h"
#include "quicksilver.h"

struct public_key;
typedef struct public_key public_key;
typedef struct public_key_ring public_key_ring;
typedef struct cbc_tag cbc_tag;

void owf_constraints_prover(quicksilver_state* state, const public_key* pk);
void owf_constraints_verifier(quicksilver_state* state, const public_key* pk);
void owf_constraints_prover_all_branches(quicksilver_state* state, const public_key_ring* pk);
void owf_constraints_verifier_all_branches(quicksilver_state* state, const public_key_ring* pk);
void owf_constraints_prover_all_branches_and_tag(quicksilver_state* state, const public_key_ring* pk_ring, const public_key* tag0, const public_key* tag1);
void owf_constraints_verifier_all_branches_and_tag(quicksilver_state* state, const public_key_ring* pk_ring, const public_key* tag0, const public_key* tag1);
#if defined(OWF_AES_CTR)
void owf_constraints_prover_all_branches_and_tag_cbc(quicksilver_state* state, const public_key_ring* pk_ring, const cbc_tag* tag);
void owf_constraints_verifier_all_branches_and_tag_cbc(quicksilver_state* state, const public_key_ring* pk_ring, const cbc_tag* tag);
void owf_constraints_prover_all_branches_and_tag_cbc2(quicksilver_state* state, const public_key_ring* pk_ring, const cbc_tag* tag);
void owf_constraints_verifier_all_branches_and_tag_cbc2(quicksilver_state* state, const public_key_ring* pk_ring, const cbc_tag* tag);
void owf_constraints_prover_all_branches_and_tag3(quicksilver_state* state, const public_key_ring* pk_ring, const cbc_tag* tag);
void owf_constraints_verifier_all_branches_and_tag3(quicksilver_state* state, const public_key_ring* pk_ring, const cbc_tag* tag);
#endif

typedef struct
{
    quicksilver_vec_gfsecpar inv_inputs[OWF_BLOCK_SIZE * OWF_ROUNDS];
    quicksilver_vec_gfsecpar inv_outputs[OWF_BLOCK_SIZE * OWF_ROUNDS];
    #if defined(ALLOW_ZERO_SBOX)
    quicksilver_vec_gfsecpar sq_inv_inputs[OWF_BLOCK_SIZE * OWF_ROUNDS];
    quicksilver_vec_gfsecpar sq_inv_outputs[OWF_BLOCK_SIZE * OWF_ROUNDS];
    #endif
	quicksilver_vec_deg2 constraints1[OWF_BLOCK_SIZE * OWF_ROUNDS];
	quicksilver_vec_deg2 constraints2[OWF_BLOCK_SIZE * OWF_ROUNDS];
} constraints_cached;

#endif
