#ifndef PRGS_H
#define PRGS_H

#include "aes.h"

#define DEFINE_PRG_AES_CTR(name) \
	typedef aes_round_keys prg_##name##_key; \
	typedef block128 prg_##name##_iv; \
	typedef block128 prg_##name##_block; \
	typedef char prg_##name##_fixed_key; /* Unused. */ \
	/* Initialize num_keys prgs, and generate num_blocks blocks from each. */ \
	inline void prg_##name##_init( \
		prg_##name##_key* restrict prgs, const prg_##name##_fixed_key* restrict fixed_key, \
		const block_secpar* restrict keys, const prg_##name##_iv* restrict ivs, \
		size_t num_keys, uint32_t num_blocks, uint32_t counter, prg_##name##_block* restrict output) \
	{ \
		aes_keygen_ctr(prgs, keys, ivs, num_keys, num_blocks, counter, output); \
	} \
	inline void prg_##name##_gen( \
		const prg_##name##_key* restrict prgs, const prg_##name##_fixed_key* restrict fixed_key, \
		size_t num_keys, uint32_t num_blocks, uint32_t counter, prg_##name##_block* restrict output) \
	{ \
		aes_ctr(prgs, num_keys, num_blocks, counter, output); \
	}

#define DEFINE_PRG_RIJNDAEL_FIXED_KEY_CTR(name) \
	typedef block_secpar prg_##name##_key; \
	typedef char prg_##name##_iv; /* Unused. */ \
	typedef block_secpar prg_##name##_block; \
	typedef rijndael_round_keys prg_##name##_fixed_key; \
	/* Initialize num_keys prgs, and generate num_blocks blocks from each. */ \
	inline void prg_##name##_init( \
		prg_##name##_key* restrict prgs, const prg_##name##_fixed_key* restrict fixed_key, \
		const block_secpar* restrict keys, const prg_##name##_iv* restrict ivs, \
		size_t num_keys, uint32_t num_blocks, uint32_t counter, prg_##name##_block* restrict output) \
	{ \
		memcpy(prgs, keys, num_keys * sizeof(keys[0])); \
		rijndael_fixed_key_ctr(fixed_key, prgs, num_keys, num_blocks, counter, output); \
	} \
	inline void prg_##name##_gen( \
		const prg_##name##_key* restrict prgs, const prg_##name##_fixed_key* restrict fixed_key, \
		size_t num_keys, uint32_t num_blocks, uint32_t counter, prg_##name##_block* restrict output) \
	{ \
		rijndael_fixed_key_ctr(fixed_key, prgs, num_keys, num_blocks, counter, output); \
	}

#if defined(PRG_AES_CTR)
#define PRG_VOLE_PREFERRED_WIDTH AES_PREFERRED_WIDTH
#define PRG_VOLE_PREFERRED_WIDTH_SHIFT AES_PREFERRED_WIDTH_SHIFT
DEFINE_PRG_AES_CTR(vole)
#elif defined(PRG_RIJNDAEL_EVEN_MANSOUR)
#define PRG_VOLE_PREFERRED_WIDTH FIXED_KEY_PREFERRED_WIDTH
#define PRG_VOLE_PREFERRED_WIDTH_SHIFT FIXED_KEY_PREFERRED_WIDTH_SHIFT
DEFINE_PRG_RIJNDAEL_FIXED_KEY_CTR(vole)
#endif

#if defined(TREE_PRG_AES_CTR)
#define PRG_TREE_PREFERRED_WIDTH AES_PREFERRED_WIDTH
#define PRG_TREE_PREFERRED_WIDTH_SHIFT AES_PREFERRED_WIDTH_SHIFT
DEFINE_PRG_AES_CTR(tree)
#elif defined(TREE_PRG_RIJNDAEL_EVEN_MANSOUR)
#define PRG_TREE_PREFERRED_WIDTH FIXED_KEY_PREFERRED_WIDTH
#define PRG_TREE_PREFERRED_WIDTH_SHIFT FIXED_KEY_PREFERRED_WIDTH_SHIFT
DEFINE_PRG_RIJNDAEL_FIXED_KEY_CTR(tree)
#endif

#if defined(LEAF_PRG_AES_CTR)
#define PRG_LEAF_PREFERRED_WIDTH AES_PREFERRED_WIDTH
#define PRG_LEAF_PREFERRED_WIDTH_SHIFT AES_PREFERRED_WIDTH_SHIFT
DEFINE_PRG_AES_CTR(leaf)
#elif defined(LEAF_PRG_RIJNDAEL_EVEN_MANSOUR)
#define PRG_LEAF_PREFERRED_WIDTH FIXED_KEY_PREFERRED_WIDTH
#define PRG_LEAF_PREFERRED_WIDTH_SHIFT FIXED_KEY_PREFERRED_WIDTH_SHIFT
DEFINE_PRG_RIJNDAEL_FIXED_KEY_CTR(leaf)
#endif

#undef DEFINE_PRG_AES_CTR
#undef DEFINE_PRG_RIJNDAEL_FIXED_KEY_CTR

#endif
