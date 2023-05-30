#include "vole_params.h"

#define EXTERN_DEFINE_PRG(name) \
	extern inline void prg_##name##_init( \
		prg_##name##_key* restrict prgs, const prg_##name##_fixed_key* restrict fixed_key, \
		const block_secpar* restrict keys, const prg_##name##_iv* restrict ivs, \
		size_t num_keys, uint32_t num_blocks, uint32_t counter, prg_##name##_block* restrict output); \
	extern inline void prg_##name##_gen( \
		const prg_##name##_key* restrict prgs, const prg_##name##_fixed_key* restrict fixed_key, \
		size_t num_keys, uint32_t num_blocks, uint32_t counter, prg_##name##_block* restrict output);

EXTERN_DEFINE_PRG(vole)
EXTERN_DEFINE_PRG(tree)
EXTERN_DEFINE_PRG(leaf)

extern inline void init_fixed_keys(
	prg_tree_fixed_key* fixed_key_tree, prg_leaf_fixed_key* fixed_key_leaf,
	block_secpar iv);
