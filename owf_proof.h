#ifndef OWF_PROOF_H
#define OWF_PROOF_H

#include "aes.h"
#include "quicksilver.h"

#if defined(OWF_AES_CTR)

#define OWF_ROUNDS AES_ROUNDS
#define OWF_BLOCK_SIZE 16
#define OWF_BLOCKS ((SECURITY_PARAM + 127) / 128)

#if SECURITY_PARAM == 256
#define OWF_KEY_SCHEDULE_PERIOD 16
#else
#define OWF_KEY_SCHEDULE_PERIOD (SECURITY_PARAM / 8)
#endif

#define OWF_KEY_SCHEDULE_CONSTRAINTS (4 * (((AES_ROUNDS + 1) * 16 - 1) / OWF_KEY_SCHEDULE_PERIOD))

#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR)

#define OWF_KEY_SCHEDULE_CONSTRAINTS 0
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

void owf_constraints_prover(quicksilver_state* state);
void owf_constraints_verifier(quicksilver_state* state);

#endif
