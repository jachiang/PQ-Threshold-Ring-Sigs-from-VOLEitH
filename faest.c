#include "faest.h"
#include "faest_details.h"

#include <stdalign.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hash.h"
#include "quicksilver.h"
#include "owf_proof.h"
#include "vector_com.h"
#include "vole_commit.h"
#include "vole_check.h"


void unpack_secret_key(secret_key* unpacked, const unsigned char* packed)
{
	memcpy(&unpacked->pk.iv, packed, sizeof(unpacked->pk.iv));
	memcpy(&unpacked->sk, packed + sizeof(unpacked->pk.iv), sizeof(unpacked->sk));

#if defined(OWF_AES_CTR)
	aes_keygen(&unpacked->round_keys, unpacked->sk);
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked->pk.fixed_key, unpacked->pk.iv);
#endif
}

void pack_public_key(unsigned char* packed, const public_key* unpacked)
{
	memcpy(packed, &unpacked->iv, sizeof(unpacked->iv));
	memcpy(packed + sizeof(unpacked->iv), &unpacked->owf_output[0], sizeof(unpacked->owf_output));
}

void unpack_public_key(public_key* unpacked, const unsigned char* packed)
{
	memcpy(&unpacked->iv, packed, sizeof(unpacked->iv));
	memcpy(&unpacked->owf_output[0], packed + sizeof(unpacked->iv), sizeof(unpacked->owf_output));
#if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
	rijndael_keygen(&unpacked->fixed_key, unpacked->iv);
#endif
}

bool compute_witness(secret_key* sk)
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
	return true;
}

bool faest_unpack_sk_and_get_pubkey(unsigned char* pk_packed, const unsigned char* sk_packed, secret_key* sk)
{
	unpack_secret_key(sk, sk_packed);
	if (!compute_witness(sk))
		return false;

	pack_public_key(pk_packed, &sk->pk);
	return true;
}

bool faest_pubkey(unsigned char* pk_packed, const unsigned char* sk_packed)
{
	secret_key sk;
	return faest_unpack_sk_and_get_pubkey(pk_packed, sk_packed, &sk);
}

bool faest_sign(unsigned char* signature, const unsigned char* msg, size_t msg_len, const unsigned char* sk_packed, const unsigned char* random_seed, size_t random_seed_len)
{
	secret_key sk;
	unsigned char pk_packed[FAEST_PUBLIC_KEY_BYTES];
	if (!faest_unpack_sk_and_get_pubkey(pk_packed, sk_packed, &sk))
		return false;

	// TODO: Domain separation.

	// TODO: Do we need to domain separate by the faest parameters?

	block_2secpar mu;
	hash_state hasher;
	hash_init(&hasher);
	hash_update(&hasher, pk_packed, FAEST_PUBLIC_KEY_BYTES);
	hash_update(&hasher, msg, msg_len);
	hash_final(&hasher, &mu, sizeof(mu));

	block_secpar seed;
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	if (random_seed)
		hash_update(&hasher, &random_seed, random_seed_len);
	hash_final(&hasher, &seed, sizeof(seed));

	block_secpar* forest =
		aligned_alloc(alignof(block_secpar), VECTOR_COMMIT_NODES * sizeof(block_secpar));
	vole_block* u =
		aligned_alloc(alignof(vole_block), VOLE_COL_BLOCKS * sizeof(vole_block));
	vole_block* v =
		aligned_alloc(alignof(vole_block), SECURITY_PARAM * VOLE_COL_BLOCKS * sizeof(vole_block));
	size_t vole_commit_size = vole_commit(seed, forest, u, v, signature);

	uint8_t chal1[VOLE_CHECK_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &mu, sizeof(mu));
	hash_update(&hasher, signature, vole_commit_size);
	hash_final(&hasher, &chal1[0], sizeof(chal1));

	uint8_t* vole_check_start = signature + vole_commit_size;
	vole_check_sender(u, v, chal1, vole_check_start);

	free(forest);

	uint8_t* correction_start = vole_check_start + VOLE_CHECK_HASH_BYTES;
	size_t remainder = (WITNESS_BITS / 8) % (16 * VOLE_BLOCK);
	for (size_t i = 0; i < WITNESS_BLOCKS - (remainder != 0); ++i)
	{
		vole_block correction = vole_block_xor(u[i], sk.witness[i]);
		memcpy(correction_start + i * sizeof(vole_block), &correction, sizeof(vole_block));
	}
	if (remainder)
	{
		vole_block correction = vole_block_xor(u[WITNESS_BLOCKS - 1], sk.witness[WITNESS_BLOCKS - 1]);
		memcpy(correction_start + (WITNESS_BLOCKS - 1) * sizeof(vole_block), &correction, remainder);
	}

	uint8_t chal2[QUICKSILVER_CHALLENGE_BYTES];
	hash_init(&hasher);
	hash_update(&hasher, &chal1, sizeof(chal1));
	hash_update(&hasher, vole_check_start, VOLE_CHECK_HASH_BYTES + (WITNESS_BITS / 8));
	hash_final(&hasher, &chal2[0], sizeof(chal2));

	block_secpar* macs =
		aligned_alloc(alignof(block_secpar), VOLE_ROWS_PADDED * sizeof(block_secpar));

	static_assert(VOLE_ROWS_PADDED % TRANSPOSE_BITS_ROWS == 0);
	transpose_secpar(v, macs, VOLE_COL_STRIDE, VOLE_ROWS_PADDED);

	quicksilver_state qs;
	memcpy(&u[0], &sk.witness[0], WITNESS_BITS / 8);
	quicksilver_init_prover(&qs, (uint8_t*) &u[0], macs, OWF_NUM_CONSTRAINTS, chal2);

	free(u);
	free(v);

	return true;
}

bool faest_verify(const unsigned char* signature, const unsigned char* msg, size_t msg_len, const unsigned char* pk_packed)
{
	// TODO
}
