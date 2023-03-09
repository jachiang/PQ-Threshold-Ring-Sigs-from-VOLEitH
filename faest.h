#include "config.h"
#include <stdbool.h>
#include <stddef.h>

#define FAEST_SECRET_KEY_BYTES (SECURITY_PARAM / 8)
#define FAEST_PUBLIC_KEY_BYTES (2 * SECURITY_PARAM / 8)
#define FAEST_SIGNATURE_BYTES 0 /* TODO */

// Random seed can be set to null for deterministic signatures.

void faest_pubkey(unsigned char* public_key, const unsigned char* secret_key);
void faest_sign(unsigned char* signature, const unsigned char* msg, size_t msg_len, const unsigned char* secret_key, const unsigned char* random_seed);
bool faest_verify(const unsigned char* signature, const unsigned char* msg, size_t msg_len, const unsigned char* public_key);
