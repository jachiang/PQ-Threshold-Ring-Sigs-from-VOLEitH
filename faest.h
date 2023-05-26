#include "config.h"
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

bool faest_pubkey(unsigned char* pk_packed, const unsigned char* sk_packed);
void faest_sign(unsigned char* signature, const unsigned char* msg, size_t msg_len, const unsigned char* secret_key, const unsigned char* random_seed);
bool faest_verify(const unsigned char* signature, const unsigned char* msg, size_t msg_len, const unsigned char* public_key);
