#ifndef FAEST_DETAILS_H
#define FAEST_DETAILS_H

#include "aes.h"
#include "block.h"
#include "owf_proof.h"
#include "vole_params.h"

typedef struct public_key
{
#if defined(OWF_AES_CTR)
	owf_block owf_input[OWF_BLOCKS];
	owf_block owf_output[OWF_BLOCKS];

#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	block_secpar owf_input[1];
	rijndael_round_keys fixed_key;
	owf_block owf_output[OWF_BLOCKS];

#elif defined(OWF_RAIN_3) || defined(OWF_RAIN_4)
	block_secpar owf_input[1];
	owf_block owf_output[OWF_BLOCKS];

#elif defined(OWF_MQ_2_8) || defined(OWF_MQ_2_1)
	// Should really be called mq_A_b_seed, but instead call it owf_input for compatibility.
	block_secpar owf_input[1];
	block_secpar* mq_A_b;
	// Length: MQ_A_B_LENGTH

	poly_secpar_vec mq_y_gfsecpar[OWF_NUM_CONSTRAINTS];
	uint8_t owf_output[MQ_N_BYTES];
#endif

} public_key;

#if defined(OWF_AES_CTR)
typedef struct cbc_tag
{
	// Note: First bit of each tag input block is ignored.
	owf_block owf_inputs[TAGGED_RING_CBC_OWF_NUM];
	owf_block owf_output[1];
	owf_block owf_outputs[TAGGED_RING_CBC_OWF_NUM]; // for testing purpose.
} cbc_tag;
#endif

typedef struct public_key_ring
{
	public_key* pubkeys;  // 1st owf
	public_key* pubkeys1; // 2nd owf
	public_key* pubkeys2; // 3rd owf (TODO: Deprecate)
	public_key* pubkeys3; // 4th owf (TODO: Deprecate)
} public_key_ring;

typedef struct
{
	// Consistency across pk, pk1, pk2, pk3:
	// AES: owf key (sk) is same for all 4 owf.
	// EM: owf_input is same for all 4 owf.
	public_key pk;   // 1st pk owf
	public_key pk1;  // 2nd pk owf
	public_key pk2;  // 3rd pk owf (TODO: Deprecate)
	public_key pk3;  // 4th pk owf (TODO: Deprecate)
	public_key tag;  // 1st tag owf (TODO: Deprecate)
	public_key tag1;  // 2nd tag owf (TODO: Deprecate)
#if defined(OWF_AES_CTR)
	cbc_tag tag_cbc; // Tagged ring sigs.
#endif
	uint32_t idx;
#if defined(OWF_MQ_2_8) || defined(OWF_MQ_2_1)
	uint8_t sk[MQ_N_BYTES];
#else
	block_secpar sk;
#endif
#if defined(OWF_AES_CTR)
	aes_round_keys round_keys;
#endif
	vole_block witness[WITNESS_BLOCKS];
	// TODO: tagged_witness.
	vole_block ring_witness[RING_WITNESS_BLOCKS];
	vole_block tagged_ring_witness[TAGGED_RING_WITNESS_BLOCKS]; // JC: Key-Sched-witness | OWF1-witness | OWF2-witness | ... | Tag-OWF-witness
	vole_block tagged_ring_cbc_witness[TAGGED_RING_CBC_WITNESS_BLOCKS]; // JC: TODO: deprecate tagged_ring_witness.
	vole_block tagged_ring_witness3[TAGGED_RING_WITNESS_BLOCKS3]; // JC: Key-Sched-witness | OWF1-witness | OWF2-witness | ... | Tag-OWF-witness
} secret_key;

void faest_free_public_key(public_key* pk);
void faest_free_secret_key(secret_key* sk);

bool faest_unpack_secret_key(secret_key* unpacked, const uint8_t* packed, bool ring);
#if (TAGGED_RING_PK_OWF_NUM == 2)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1);
#elif (TAGGED_RING_PK_OWF_NUM == 3)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1, const uint8_t* owf_input2);
#elif (TAGGED_RING_PK_OWF_NUM == 4)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1, const uint8_t* owf_input2, const uint8_t* owf_input3);
#endif
bool faest_unpack_secret_key_for_tag(secret_key* unpacked_sk, const uint8_t* tag_owf_input0, const uint8_t* tag_owf_input1);
void faest_pack_public_key(uint8_t* packed, const public_key* unpacked);
void faest_unpack_public_key(public_key* unpacked, const uint8_t* packed);
bool faest_compute_witness(secret_key* sk, bool ring, bool tag);
#if defined(OWF_AES_CTR)
bool faest_compute_witness_cbc(secret_key* sk);
bool faest_compute_witness_cbc2(secret_key* sk);
bool faest_compute_witness3(secret_key* sk, bool ring, bool tag);
bool faest_unpack_secret_key_for_cbc_tag(secret_key* unpacked_sk, const uint8_t* tag_in0, const uint8_t* tag_in1, const uint8_t* tag_in2, const uint8_t* tag_in3);
bool faest_unpack_secret_key_for_cbc_tag2(secret_key* unpacked_sk, const uint8_t* tag_in0, const uint8_t* tag_in1, const uint8_t* tag_in2, const uint8_t* tag_in3);
bool faest_unpack_secret_key_for_tag3(secret_key* unpacked_sk, const uint8_t* tag_owf_input0, const uint8_t* tag_owf_input1);
#endif
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed, secret_key* sk);

#endif // FAEST_DETAILS_H
