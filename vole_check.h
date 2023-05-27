#ifndef VOLE_CHECK_H
#define VOLE_CHECK_H

#include "universal_hash.h"

#define VOLE_CHECK_HASH_BYTES (SECURITY_PARAM + 1) /* TODO */
#define VOLE_CHECK_CHALLENGE_BYTES ((5 * SECURITY_PARAM + 64) / 8)
#define VOLE_CHECK_RESPONSE_BYTES (VOLE_CHECK_HASH_BYTES + 2 * SECURITY_PARAM)

void vole_check_sender(
	const vole_block* restrict u, const vole_block* restrict v,
	const unsigned char* restrict challenge, unsigned char* restrict response);

bool vole_check_receiver(
	const vole_block* restrict q, const uint8_t* restrict delta,
	const unsigned char* restrict challenge, const unsigned char* restrict response);


#endif
