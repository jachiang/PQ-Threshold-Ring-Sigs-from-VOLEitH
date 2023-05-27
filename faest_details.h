#ifndef FAEST_DETAILS_H
#define FAEST_DETAILS_H

#include "aes.h"
#include "block.h"

#if defined(OWF_AES_CTR)

#define OWF_OUTPUT_BLOCKS ((SECURITY_PARAM + 127) / 128)
typedef block128 owf_block;
inline owf_block owf_block_xor(owf_block x, owf_block y) { return block128_xor(x, y); }
inline owf_block owf_block_set_low32(uint32_t x) { return block128_set_low32(x); }

#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)

#define OWF_OUTPUT_BLOCKS 1
typedef block_secpar owf_block;
inline owf_block owf_block_xor(owf_block x, owf_block y) { return block_secpar_xor(x, y); }
inline owf_block owf_block_set_low32(uint32_t x) { return block_secpar_set_low32(x); }

#else
#error Unsupported OWF configuration.
#endif

typedef struct
{
#if defined(OWF_AES_CTR)
	block128 iv;
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	block_secpar iv;
	rijndael_round_keys fixed_key;
#endif
	owf_block owf_output[OWF_OUTPUT_BLOCKS];
} public_key;

typedef struct
{
	public_key pk;
	block_secpar sk;
#if defined(OWF_AES_CTR)
	aes_round_keys round_keys;
#endif
	vole_block witness[WITNESS_BLOCKS];
} secret_key;

void unpack_secret_key(secret_key* unpacked, const unsigned char* packed);
void pack_public_key(unsigned char* packed, const public_key* unpacked);
void unpack_public_key(public_key* unpacked, const unsigned char* packed);
bool compute_witness(secret_key* sk);
bool faest_unpack_sk_and_get_pubkey(unsigned char* pk_packed, const unsigned char* sk_packed, secret_key* sk);

#endif // FAEST_DETAILS_H
