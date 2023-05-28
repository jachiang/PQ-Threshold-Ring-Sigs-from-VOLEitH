#include "config.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(OWF_AES_CTR)
#define FAEST_IV_BYTES 16
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)
#define FAEST_IV_BYTES (SECURITY_PARAM / 8)
#endif

#define FAEST_SECRET_KEY_BYTES ((SECURITY_PARAM / 8) + FAEST_IV_BYTES)

#if defined(OWF_AES_CTR) && SECURITY_PARAM == 192
#define FAEST_PUBLIC_KEY_BYTES (32 + FAEST_IV_BYTES)
#else
#define FAEST_PUBLIC_KEY_BYTES FAEST_SECRET_KEY_BYTES
#endif

#define FAEST_SIGNATURE_BYTES 0 /* TODO */

// Random seed can be set to null for deterministic signatures.

bool faest_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed);
bool faest_sign(
	uint8_t* signature, const uint8_t* msg, size_t msg_len, const uint8_t* sk_packed,
	const uint8_t* random_seed, size_t random_seed_len);
bool faest_verify(const uint8_t* signature, const uint8_t* msg, size_t msg_len,
                  const uint8_t* pk_packed);
