#include "faest.h"

#include <stdbool.h>
#include "block.h"
#include "aes.h"

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

static void unpack_secret_key(secret_key* unpacked, const unsigned char* packed)
{
	memcpy(&unpacked->pk.iv, packed, sizeof(unpacked->pk.iv));
	memcpy(&unpacked->sk, packed + sizeof(unpacked->pk.iv), sizeof(unpacked->sk));

#if defined(OWF_AES_CTR)
	aes_keygen(&unpacked->round_keys, unpacked->sk);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked->pk.fixed_key, iv);
#endif
}

static void pack_public_key(unsigned char* packed, const public_key* unpacked)
{
	memcpy(packed, &unpacked->iv, sizeof(unpacked->iv));
	memcpy(packed + sizeof(unpacked->iv), &unpacked->owf_output[0], sizeof(unpacked->owf_output));
}

static void unpack_public_key(public_key* unpacked, const unsigned char* packed)
{
	// TODO
}

static bool compute_witness(secret_key* sk)
{
#if defined(OWF_AES_CTR)
	owf_block key0_combined = sk->round_keys.keys[0];
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	owf_block key0_combined = owf_block_xor(sk->pk.fixed_key.keys[0], sk->sk);
#endif

	for (uint32_t i = 0; i < OWF_OUTPUT_BLOCKS; ++i)
		sk->pk.owf_output[i] = owf_block_xor(owf_block_set_low32(i), key0_combined);

	// TODO: pack witness into sk->witness.
	for (unsigned int round = 1; round <= AES_ROUNDS; ++round)
	{
		for (uint32_t i = 0; i < OWF_OUTPUT_BLOCKS; ++i)
		{
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
#endif
		}
	}

#if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	for (uint32_t i = 0; i < OWF_OUTPUT_BLOCKS; ++i)
		sk->pk.owf_output[i] = owf_block_xor(sk->pk.owf_output[i], sk->sk);
#endif

	// TODO: Use the witness to check if this is a valid key.
}

bool faest_pubkey(unsigned char* pk_packed, const unsigned char* sk_packed)
{
	secret_key sk;
	unpack_secret_key(&sk, sk_packed);

	bool valid = compute_witness(&sk);
	if (!valid)
		return false;

	pack_public_key(pk_packed, &sk.pk);
	return true;
}

void faest_sign(unsigned char* signature, const unsigned char* msg, size_t msg_len, const unsigned char* secret_key, const unsigned char* random_seed)
{
    // TODO
}

bool faest_verify(const unsigned char* signature, const unsigned char* msg, size_t msg_len, const unsigned char* public_key)
{
    // TODO
}
