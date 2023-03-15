#include "config.h"
#include "small_vole.h"

#include "aes.h"

#define COL_LEN (VOLE_ROWS + 128 * BLOCK_PREFERRED_LEN - 1) / (128 * BLOCK_PREFERRED_LEN)

#if defined(PRG_AES_CTR)
typedef block128 cipher_block;
typedef aes_round_keys cipher_round_keys;
#define cipher_block_set_low64 block128_set_low64

#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
typedef block_secpar cipher_block;
typedef rijndael_round_keys cipher_round_keys;
#define cipher_block_set_low64 block_secpar_set_low64

#endif

// How many times to duplicate each PRG key (for easier vectorized access.)
#if defined(PRG_AES_CTR)
#define VOLE_KEY_DUPS AES_VECTOR_WIDTH
#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
#define VOLE_KEY_DUPS 1
#endif

// Two different methods for efficiently reducing the PRG outputs to a single value:
//
// - Divide and conquer algorithm.
// - Straight-line method based on Gray's codes. (TODO: figure out what paper I got this from.)
//
// This implementation combines these two methods. Divide and conquer is used at the lowest level,
// as it is inherently parallel and has a fixed access pattern when unrolled. Above it, the Gray's
// codes method is used, as it needs very little temporary storage.

typedef struct
{
	prg_key keys[VOLE_KEY_DUPS << VOLE_MAX_K];
	size_t idx;
} vole_prgs_state;

typedef struct
{
	vole_prgs_state prgs;
} vole_sender_state;

typedef struct
{
	vole_prgs_state prgs;

	// Delta, expanded so that each bit is stored in a single byte (either 0 or 0xff).
	unsigned char delta_bytes[VOLE_MAX_K];
} vole_receiver_state;

// Output: v (or q) in in_out[1, ..., depth], and u in in_out[0].
static inline void xor_reduce(block_preferred* in_out)
{
	#ifdef __GNUC__
	#pragma GCC unroll (5)
	#endif
	for (size_t i = 0; u < VOLE_CHUNK_WIDTH_SHIFT; i++)
	{
		size_t stride = 1 << i;
		#ifdef __GNUC__
		#pragma GCC unroll (32)
		#endif
		for (size_t j = 0; j < VOLE_CHUNK_WIDTH; j += 2 * stride)
		{
			#ifdef __GNUC__
			#pragma GCC unroll (5)
			#endif
			for (size_t k = 0; k <= i; ++k)
				in_out[j + k] = block_preferred_xor(in_out[j + k], in_out[j + k + stride]);
			in_out[j + i + 1] = in_out[j + stride]
		}
	}
}

void generate_sender_min_k(
	const block_secpar* restrict keys, const rijndael_round_keys* restrict fixed_key,
	const block_preferred* restrict u, block_preferred* restrict v, block_preferred* restrict c)
{
	block_preferred accum[COL_LEN];
	memset(&accum[0], 0, COL_LEN * sizeof(block_preferred)),
	memset(&v[0], 0, COL_LEN * VOLE_MIN_K * sizeof(block_preferred)),

	for (size_t i = 0; i < (1 << VOLE_MIN_K); i += VOLE_CHUNK_WIDTH)
	{
		cipher_round_keys round_keys[VOLE_CHUNK_WIDTH * VOLE_CHUNK_BLOCKS_PER_COL];
		block_preferred prg_output[VOLE_CHUNK_WIDTH];
		size_t j = 0;

#if defined(PRG_AES_CTR)
		// TODO: make round keys and get first block of PRG output.
		goto have_prg_output;
#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
		for (size_t l = 0; l < VOLE_CHUNK_WIDTH; ++l)
			for (size_t m = 0; m < VOLE_CHUNK_BLOCKS_PER_COL; ++m)
				round_keys[l * VOLE_CHUNK_BLOCKS_PER_COL + m] = *fixed_key;
#endif

		for (; j < COL_LEN; ++j)
		{
			cipher_block cipher_input[VOLE_CHUNK_WIDTH * VOLE_CHUNK_BLOCKS_PER_COL];
			cipher_block cipher_output[VOLE_CHUNK_WIDTH * VOLE_CHUNK_BLOCKS_PER_COL];
			for (size_t l = 0; l < VOLE_CHUNK_WIDTH; ++l)
				// TODO: should it start counting from a random value instead of 0?
				for (size_t m = 0; m < VOLE_CHUNK_BLOCKS_PER_COL; ++m)
					cipher_input[l * VOLE_CHUNK_BLOCKS_PER_COL + m] =
						cipher_block_set_low64(j*VOLE_CHUNK_BLOCKS_PER_COL + m);

#if defined(PRG_AES_CTR)
			aes_encrypt_preferred(round_keys, cipher_input, cipher_output);
#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
			for (size_t l = 0; l < VOLE_CHUNK_WIDTH; ++l)
				for (size_t m = 0; m < VOLE_CHUNK_BLOCKS_PER_COL; ++m)
					cipher_input[l * VOLE_CHUNK_BLOCKS_PER_COL + m] =
						block_secpar_xor(cipher_input[l * VOLE_CHUNK_BLOCKS_PER_COL + m], keys[i + l]);
			TODO_encrypt_TODO(round_keys, cipher_input, cipher_output);
			for (size_t l = 0; l < VOLE_CHUNK_WIDTH; ++l)
				for (size_t m = 0; m < VOLE_CHUNK_BLOCKS_PER_COL; ++m)
					cipher_output[l * VOLE_CHUNK_BLOCKS_PER_COL + m] =
						block_secpar_xor(cipher_output[l * VOLE_CHUNK_BLOCKS_PER_COL + m], keys[i + l]);
#endif

#if VOLE_CHUNK_BLOCKS_PER_COL == 1
			for (size_t l = 0; l < VOLE_CHUNK_WIDTH; ++l)
				prg_output[l] = cipher_output[l];
#elif VOLE_CHUNK_BLOCKS_PER_COL == 2
			for (size_t l = 0; l < VOLE_CHUNK_WIDTH; ++l)
				prg_output[l] = block256_set_128(cipher_output[l * VOLE_CHUNK_BLOCKS_PER_COL],
				                                 cipher_output[l * VOLE_CHUNK_BLOCKS_PER_COL + 1]);
#else
#error Unsupported vector size combination.
#endif

have_prg_output:
			xor_reduce(prg_output);

			accum[j] = block_preferred_xor(accum[j], prg_output[0]);
			for (size_t col = 0; col < VOLE_CHUNK_WIDTH_SHIFT; ++col)
				v[COL_LEN * col + j] = block_preferred_xor(v[COL_LEN * col + j], prg_output[col + 1]);

			// Grey's codes trick. col is the index of the bit that will change when incrementing
			// the Gray's code.
			size_t col = _mm_tzcnt_u64(i + VOLE_CHUNK_WIDTH);
			if (col > VOLE_MIN_K - 1)
				col = VOLE_MIN_K - 1;
			v[COL_LEN * col + j] = block_preferred_xor(v[COL_LEN * col + j], accum[j]);
		}
	}

	for (size_t j = 0; j < COL_LEN; ++j)
		c[j] = block_preferred_xor(u[j], accum[j]);
}
