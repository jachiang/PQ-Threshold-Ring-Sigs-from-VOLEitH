typedef struct {
	aes_state cipher;
	size_t counter;
} prg_state;

// aes_fixed_key is unused. It's only present for compatibility with even_mansour.

inline void prg_init(prg_state* prg, const unsigned char* seed, const aes_state* aes_fixed_key)
{
	aes_init(&prg->cipher, seed);
	prg->counter = 0;
}

inline void prg_gen(prg_state* prg, unsigned char* output, size_t size, const aes_state* aes_fixed_key);

inline void prg_gen_blocks_interleaved(prg_state* prgs, unsigned char* output, size_t num_prgs, size_t num_blocks, const aes_state* aes_fixed_key);

// Expand to 2*PRG_SEED_SIZE bytes
inline void prg_double(prg_state* prg, const unsigned char* seed, unsigned char* seeds_out, const aes_state* aes_fixed_key);

// Expand to PRG_SEED_SIZE + DIGEST_SIZE bytes.
inline void prg_digest(prg_state* prg, const unsigned char* seed_in, unsigned char* seed_out, unsigned char* digest_out, const aes_state* aes_fixed_key);
