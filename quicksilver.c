#include "quicksilver.h"

void quicksilver_prove(const quicksilver_state* state, size_t witness_bits, uint8_t* proof)
{
	assert(!state->verifier);
	// TODO
}

bool quicksilver_verify(const quicksilver_state* state, size_t witness_bits, const uint8_t* proof)
{
	assert(state->verifier);
	// TODO
	return true;
}

// TODO: extern inlines.
