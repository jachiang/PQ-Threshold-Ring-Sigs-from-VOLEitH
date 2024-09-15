#ifndef FAEST_DETAILS_H
#define FAEST_DETAILS_H

#include "aes.h"
#include "block.h"
#include "config.h"
#include "owf_proof.h"
#include "vole_params.h"

typedef struct public_key
{
#if defined(OWF_AES_CTR)
	owf_block owf_input[OWF_BLOCKS];
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	block_secpar owf_input[1];
	rijndael_round_keys fixed_key;
#endif
	owf_block owf_output[OWF_BLOCKS];
} public_key;

typedef struct public_key_ring
{
	public_key* pubkeys;  // 1st owf
	public_key* pubkeys1; // 2nd owf
	public_key* pubkeys2; // 3rd owf
	public_key* pubkeys3; // 4th owf
} public_key_ring;

typedef struct
{
	// Consistency across pk, pk1, pk2, pk3:
	// AES: owf key (sk) is same for all 4 owf.
	// EM: owf_input is same for all 4 owf.
	public_key pk;   // 1st owf
	public_key pk1;  // 2nd owf
	public_key pk2;  // 3rd owf
	public_key pk3;  // 4th owf
	block_secpar sk;
	uint32_t idx;
#if defined(OWF_AES_CTR)
	aes_round_keys round_keys;
#endif
	vole_block witness[WITNESS_BLOCKS];
	vole_block ring_witness[RING_WITNESS_BLOCKS];
	vole_block tagged_ring_witness[TAGGED_RING_WITNESS_BLOCKS];
} secret_key;

bool faest_unpack_secret_key(secret_key* unpacked, const uint8_t* packed, bool ring);
#if (TAGGED_RING_OWF_NUM == 2)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1);
#elif (TAGGED_RING_OWF_NUM == 3)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1, const uint8_t* owf_input2);
#elif (TAGGED_RING_OWF_NUM == 4)
bool faest_unpack_secret_key_fixed_owf_inputs(secret_key* unpacked_sk, const uint8_t* owf_key, const uint8_t* owf_input0, const uint8_t* owf_input1, const uint8_t* owf_input2, const uint8_t* owf_input3);
#endif
void faest_pack_public_key(uint8_t* packed, const public_key* unpacked);
void faest_unpack_public_key(public_key* unpacked, const uint8_t* packed);
bool faest_compute_witness(secret_key* sk, bool ring, bool tag);
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed, secret_key* sk);
void faest_pack_pk_ring(uint8_t* pk_ring_packed, const public_key_ring* pk_ring_unpacked);
void faest_unpack_pk_ring(public_key_ring* pk_ring_unpacked, const uint8_t* pk_ring_packed);

#endif // FAEST_DETAILS_H
