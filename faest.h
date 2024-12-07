#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include "config.h"
#include "quicksilver.h"
#include "vole_check.h"
#include "vole_params.h"
#include "vector_com.h"
#include "vole_commit.h"
#include "faest_details.h"

#if defined(OWF_AES_CTR)
#define FAEST_IV_BYTES (OWF_BLOCKS * OWF_BLOCK_SIZE)
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
#define FAEST_IV_BYTES (SECURITY_PARAM / 8)
#elif defined(OWF_RAIN_3) || defined(OWF_RAIN_4)
#define FAEST_IV_BYTES (SECURITY_PARAM / 8)
#elif defined(OWF_MQ_2_1)
#define FAEST_IV_BYTES (SECURITY_PARAM / 8)
#elif defined(OWF_MQ_2_8)
#define FAEST_IV_BYTES (SECURITY_PARAM / 8)
#endif

#if defined(OWF_MQ_2_1) || defined(OWF_MQ_2_8)
#define FAEST_SECRET_KEY_BYTES ((MQ_M*MQ_GF_BITS)/8 + FAEST_IV_BYTES)		// MQ_M is set to be divisuble by 8
#else
#define FAEST_SECRET_KEY_BYTES ((SECURITY_PARAM / 8) + FAEST_IV_BYTES)
#endif

#if defined(OWF_AES_CTR) && SECURITY_PARAM == 192
#define FAEST_PUBLIC_KEY_BYTES (32 + FAEST_IV_BYTES)
#else
#define FAEST_PUBLIC_KEY_BYTES FAEST_SECRET_KEY_BYTES
#endif

#if USE_IMPROVED_VECTOR_COMMITMENTS == 0 && ZERO_BITS_IN_CHALLENGE_3 == 0
	#define COUNTER_BYTES 0
#else
	#define COUNTER_BYTES 4
#endif

#define FAEST_SIGNATURE_BYTES ( \
	VOLE_COMMIT_SIZE + \
	VOLE_CHECK_PROOF_BYTES + \
	WITNESS_BITS / 8 + \
	QUICKSILVER_PROOF_BYTES + \
	VECTOR_COM_OPEN_SIZE + \
	SECURITY_PARAM / 8 + \
	16 + COUNTER_BYTES)

#if (FAEST_RING_HOTVECTOR_DIM == 1)
#define FAEST_RING_PROOF_ELEMS (2)
#elif  (FAEST_RING_HOTVECTOR_DIM == 2)
#define FAEST_RING_PROOF_ELEMS (3)
#elif  (FAEST_RING_HOTVECTOR_DIM == 4)
#define FAEST_RING_PROOF_ELEMS (5)
#endif

#define FAEST_TAGGED_SIGNATURE_BYTES ( \
	VOLE_TAGGED_COMMIT_SIZE + \
	VOLE_CHECK_PROOF_BYTES + \
	WITNESS_BITS4 / 8 + \
	QUICKSILVER_PROOF_BYTES * FAEST_RING_PROOF_ELEMS + \
	VECTOR_COM_OPEN_SIZE + \
	SECURITY_PARAM / 8 + \
	16 + COUNTER_BYTES)

#define FAEST_RING_SIGNATURE_BYTES ( \
	VOLE_RING_COMMIT_SIZE + \
	VOLE_CHECK_PROOF_BYTES + \
	RING_WITNESS_BITS / 8 + \
	QUICKSILVER_PROOF_BYTES * FAEST_RING_PROOF_ELEMS + \
	VECTOR_COM_OPEN_SIZE + \
	SECURITY_PARAM / 8 + \
	16 + COUNTER_BYTES)

#define FAEST_CBC_TAGGED_RING_SIGNATURE_BYTES ( \
	VOLE_CBC_TAGGED_RING_COMMIT_SIZE + \
	VOLE_CHECK_PROOF_BYTES + \
	CBC_TAGGED_RING_WITNESS_BITS / 8 + \
	QUICKSILVER_PROOF_BYTES * FAEST_RING_PROOF_ELEMS + \
	VECTOR_COM_OPEN_SIZE + \
	SECURITY_PARAM / 8 + \
	16 + COUNTER_BYTES)

#define FAEST_TAGGED_RING_SIGNATURE_BYTES ( \
	VOLE_TAGGED_RING_COMMIT_SIZE + \
	VOLE_CHECK_PROOF_BYTES + \
	TAGGED_RING_WITNESS_BITS / 8 + \
	QUICKSILVER_PROOF_BYTES * FAEST_RING_PROOF_ELEMS + \
	VECTOR_COM_OPEN_SIZE + \
	SECURITY_PARAM / 8 + \
	16 + COUNTER_BYTES)

// Find the public key corresponding to a given secret key. Returns true if sk_packed is a valid
// secret key, and false otherwise. For key generation, this function is intended to be called
// repeatedly on random values of sk_packed until a valid key is found. pk_packed must be
// FAEST_PUBLIC_KEY_BYTES long, while sk_packed must be FAEST_SECRET_KEY_BYTES long.
bool faest_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed);

// Generate a signature (of length FAEST_SIGNATURE_BYTES) for a message msg (of length msg_len)
// using a secret key sk_packed (of length FAEST_SECRET_KEY_BYTES) and randomness random_seed (of
// length random_seed_len). random_seed can be set to null for deterministic signatures. The
// randomness is mixed with pseudorandom bits generated from secret key and the message, to protect
// against bad randomness. Returns true if sk_packed is a valid secret key, and false otherwise.
bool faest_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, const uint8_t* sk_packed,
	const uint8_t* random_seed, size_t random_seed_len);

// TODO: input packed key/tag
bool faest_tagged_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, secret_key* sk,
	const public_key* pk, const public_key* tag, const uint8_t* random_seed, size_t random_seed_len);

// TODO: input packed keys
bool faest_ring_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, secret_key* sk, const public_key_ring* pk_ring, const uint8_t* random_seed, size_t random_seed_len);

#if defined(OWF_AES_CTR)
// TODO: input packed keys/tags
bool faest_cbc_tagged_ring_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, secret_key* sk, const public_key_ring* pk_ring, const cbc_tag* tag, const uint8_t* random_seed, size_t random_seed_len);
#endif
// TODO: deprecate
bool faest_tagged_ring_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, secret_key* sk, const public_key_ring* pk_ring,
	public_key* pk_tag0, public_key* pk_tag1, const uint8_t* random_seed, size_t random_seed_len);

// Verify a signature (of length FAEST_SIGNATURE_BYTES) for a message msg (of length msg_len)
// using a public key pk_packed (of length FAEST_PUBLIC_KEY_BYTES). Returns true for a valid
// signature and false otherwise.
bool faest_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  const uint8_t* pk_packed);

// TODO: input packed key/tag
bool faest_tagged_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  		 const public_key* pk, const public_key* tag);
// TODO: input packed keys
bool faest_ring_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  	   const public_key_ring* pk_ring);

#if defined(OWF_AES_CTR)
// TODO: input packed keys/tags
bool faest_cbc_tagged_ring_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  	   const public_key_ring* pk_ring, const cbc_tag* tag);
#endif
// TODO: deprecate
bool faest_tagged_ring_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  	   const public_key_ring* pk_ring, public_key* pk_tag0, public_key* pk_tag1);