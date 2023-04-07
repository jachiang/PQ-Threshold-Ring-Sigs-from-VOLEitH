#include "faest.h"
#include "block.h"
#include "aes.h"

void faest_pubkey(unsigned char* public_key, const unsigned char* secret_key)
{
#if defined(OWF_AES_CTR)
	block128 iv;
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	block_secpar iv;
#endif

	block_secpar sk;
	memcpy(&iv, secret_key, sizeof(iv));
	memcpy(&sk, secret_key + sizeof(iv), sizeof(sk));

#if defined(OWF_AES_CTR)
	aes_round_keys round_keys;
	block128 cipher_output[(SECURITY_PARAM + 127) / 128];
	aes_keygen_ctr(&round_keys, &sk, &iv, 1, (SECURITY_PARAM + 127) / 128, 0, &cipher_output[0]);

#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_round_keys fixed_key;
	rijndael_keygen(&fixed_key, iv);

	block_secpar cipher_output[1];
	rijndael_fixed_key_ctr(&fixed_key, &sk, 1, 1, 0, &cipher_output[0]);

#else
#error Unsupported OWF configuration.
#endif

	memcpy(public_key, &iv, sizeof(iv));
	memcpy(public_key + sizeof(iv), &cipher_output[0], sizeof(cipher_output));
}
