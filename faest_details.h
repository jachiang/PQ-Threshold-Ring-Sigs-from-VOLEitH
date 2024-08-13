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
	struct public_key pubkeys[FAEST_RING_SIZE];
} public_key_ring;

typedef struct
{
	public_key pk;
	block_secpar sk;
	uint8_t idx[FAEST_RING_BITS];
#if defined(OWF_AES_CTR)
	aes_round_keys round_keys;
#endif
	vole_block witness[WITNESS_BLOCKS];
	vole_block ring_witness[RING_WITNESS_BLOCKS];
} secret_key;

bool faest_unpack_secret_key(secret_key* unpacked, const uint8_t* packed, bool ring);
void faest_pack_public_key(uint8_t* packed, const public_key* unpacked);
void faest_unpack_public_key(public_key* unpacked, const uint8_t* packed);
bool faest_compute_witness(secret_key* sk, bool ring);
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed, secret_key* sk);

#endif // FAEST_DETAILS_H
