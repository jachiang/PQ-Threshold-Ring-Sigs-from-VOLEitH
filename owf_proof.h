#ifndef OWF_PROOF_H
#define OWF_PROOF_H

#if defined(OWF_AES_CTR)

// Number of applications of the round function per encryption (need OWF_ROUNDS + 1 round keys).
#define OWF_ROUNDS AES_ROUNDS
// Block size of the cipher
#define OWF_BLOCK_SIZE 16
// Number of blocks encrypted in the OWF.
// (1 for 128 bit, 2 for 192/256 bit to compensate for the 128 bit block size)
#define OWF_BLOCKS ((SECURITY_PARAM + 127) / 128)

// Spacing in bytes of the sub_words operation in the key schedule.
#if SECURITY_PARAM == 256
#define OWF_KEY_SCHEDULE_PERIOD 16
#else
#define OWF_KEY_SCHEDULE_PERIOD (SECURITY_PARAM / 8)
#endif

// Number of S-boxes in the key schedule.
#define OWF_KEY_SCHEDULE_CONSTRAINTS \
	(4 * (((AES_ROUNDS + 1) * 16 - SECURITY_PARAM / 8 + \
	       OWF_KEY_SCHEDULE_PERIOD - 1) / OWF_KEY_SCHEDULE_PERIOD))
#define OWF_KEY_SCHEDULE_WITNESS_BITS (SECURITY_PARAM / 8 + OWF_KEY_SCHEDULE_CONSTRAINTS)

#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)

#define OWF_KEY_SCHEDULE_CONSTRAINTS 0
#define OWF_KEY_SCHEDULE_WITNESS_BITS 0
#define OWF_BLOCK_SIZE (SECURITY_PARAM / 8)
#define OWF_BLOCKS 1

#if SECURITY_PARAM == 128
#define OWF_ROUNDS AES_ROUNDS
#elif SECURITY_PARAM == 192
#define OWF_ROUNDS RIJNDAEL192_ROUNDS
#elif SECURITY_PARAM == 256
#define OWF_ROUNDS RIJNDAEL256_ROUNDS
#endif

#else

#error "Unsupported one-way function."
#endif

#define OWF_NUM_CONSTRAINTS (OWF_BLOCKS * OWF_BLOCK_SIZE * OWF_ROUNDS + OWF_KEY_SCHEDULE_CONSTRAINTS)
#define WITNESS_BITS (OWF_BLOCKS * OWF_BLOCK_SIZE * (OWF_ROUNDS - 1) + OWF_KEY_SCHEDULE_WITNESS_BITS)

#include "aes.h"
#include "quicksilver.h"

void owf_constraints_prover(quicksilver_state* state);
void owf_constraints_verifier(quicksilver_state* state);

#endif
