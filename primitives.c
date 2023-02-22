#include "primitives.h"

extern inline void random_oracle_init(random_oracle_state* ro);
extern inline void random_oracle_update(random_oracle_state* ro, const char* input, size_t size);
extern inline void random_oracle_final(random_oracle_state* ro, char* digest);

extern inline void prg_init(prg_state* prg, const char* seed);
extern inline void prg_gen(prg_state* prg, char* output, size_t size);
extern inline void prg_gen_blocks_interleaved(prg_state* prgs, char* output, size_t num_prgs, size_t num_blocks);

extern inline void prg_double(prg_state* prg, const char* seed, char* output);
extern inline void prg_digest(prg_state* prg, const char* seed, char* output);

extern inline gf128 xor_128(gf128 x, gf128 y);
extern inline gf256 xor_256(gf256 x, gf256 y);

// TODO: update with all functions.
