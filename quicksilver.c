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

extern inline void quicksilver_init_hash_keys(quicksilver_state* state, const uint8_t* challenge);
extern inline void quicksilver_init_prover(
    quicksilver_state* state, const uint8_t* witness, const block_secpar* macs,
    size_t num_constraints, const uint8_t* challenge);
extern inline void quicksilver_init_verifier(
    quicksilver_state* state, const block_secpar* macs, size_t num_constraints,
    block_secpar delta, const uint8_t* challenge);
extern inline quicksilver_vec_gf2 quicksilver_get_witness_vec(const quicksilver_state* state, size_t index);
extern inline void quicksilver_final(const quicksilver_state* state, bool verifier,
        poly_secpar_vec* hash_const_secpar, poly_secpar_vec* hash_linear_secpar,
        poly_secpar_vec* hash_const_64, poly_secpar_vec* hash_linear_64);
extern inline poly_secpar_vec quicksilver_get_delta(const quicksilver_state* state);
extern inline quicksilver_vec_gf2 quicksilver_add_gf2(const quicksilver_state* state, quicksilver_vec_gf2 x, quicksilver_vec_gf2 y);
extern inline quicksilver_vec_gfsecpar quicksilver_add_gfsecpar(const quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y);
extern inline quicksilver_vec_gf2 quicksilver_zero_gf2();
extern inline quicksilver_vec_gfsecpar quicksilver_zero_gfsecpar();
extern inline quicksilver_vec_gf2 quicksilver_one_gf2(const quicksilver_state* state);
extern inline quicksilver_vec_gfsecpar quicksilver_one_gfsecpar(const quicksilver_state* state);
extern inline quicksilver_vec_gf2 quicksilver_const_gf2(const quicksilver_state* state, poly1_vec c);
extern inline quicksilver_vec_gfsecpar quicksilver_const_gfsecpar(const quicksilver_state* state, poly_secpar_vec c);
extern inline quicksilver_vec_gf2 quicksilver_mul_const_gf2(const quicksilver_state* state, quicksilver_vec_gf2 x, poly1_vec c);
extern inline quicksilver_vec_gfsecpar quicksilver_mul_const(const quicksilver_state* state, quicksilver_vec_gfsecpar x, poly_secpar_vec c);
extern inline quicksilver_vec_gfsecpar quicksilver_combine_8_bits(const quicksilver_state* state, const quicksilver_vec_gf2* qs_bits);
extern inline void quicksilver_add_product_constraints(quicksilver_state* state, quicksilver_vec_gfsecpar x, quicksilver_vec_gfsecpar y);
