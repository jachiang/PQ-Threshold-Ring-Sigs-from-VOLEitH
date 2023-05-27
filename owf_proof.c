#include "owf_proof.h"

#include "config.h"

static ALWAYS_INLINE void owf_constraints(quicksilver_state* state)
{
	// TODO
}

void owf_constraints_prover(quicksilver_state* state)
{
	assert(!state->verifier);
	owf_constraints(state);
}

void owf_constraints_verifier(quicksilver_state* state)
{
	assert(state->verifier);
	owf_constraints(state);
}
