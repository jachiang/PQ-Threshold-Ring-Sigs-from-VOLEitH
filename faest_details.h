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

typedef struct
{
	public_key pk;
#if defined(OWF_MQ_2_8) || defined(OWF_MQ_2_1)
	uint8_t sk[MQ_N_BYTES];
#else
	block_secpar sk;
#endif
#if defined(OWF_AES_CTR)
	aes_round_keys round_keys;
#endif
	vole_block witness[WITNESS_BLOCKS];
} secret_key;

void faest_free_public_key(public_key* pk);
void faest_free_secret_key(secret_key* sk);

bool faest_unpack_secret_key(secret_key* unpacked, const uint8_t* packed);
void faest_pack_public_key(uint8_t* packed, const public_key* unpacked);
void faest_unpack_public_key(public_key* unpacked, const uint8_t* packed);
bool faest_compute_witness(secret_key* sk);
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed, secret_key* sk);

#endif // FAEST_DETAILS_H
