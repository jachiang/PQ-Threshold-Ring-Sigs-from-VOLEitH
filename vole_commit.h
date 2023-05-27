#ifndef VOLE_COMMIT_H
#define VOLE_COMMIT_H

#include "block.h"

size_t vole_commit(
	block_secpar seed, block_secpar* restrict forest, block_2secpar* hashed_leaves,
	vole_block* restrict u, vole_block* restrict v, uint8_t* restrict commitment);

#endif
