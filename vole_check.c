#include "vole_check.h"

int tmp;

#ifdef NOT_DEFINED

typedef struct
{
	poly_secpar_vec matrix[4];

	hasher_gfsecpar_key key_secpar;
	hasher_gf64_key key_64;
} vole_check_challenge;

static vole_check_load_challenge load_challenge(const unsigned char* in)
{
	vole_check_load_challenge out;
	for (size_t i = 0; i < 4; ++i, in += SECURITY_PARAM / 8)
		out.matrix[i] = poly_secpar_load_dup(in);

	// TODO: Square the key.
	hasher_gfsecpar_init_key(&out, poly_secpar_load_dup(in));
	hasher_gf64_init_key(&out, poly_secpar_load_dup(in + SECURITY_PARAM / 8));
}

void vole_check_sender(
	const vole_block* restrict u, const vole_block* restrict v,
	const unsigned char* restrict challenge, unsigned char* restrict response)
{
	vole_check_challenge chal = load_challenge(challenge);

	for (size_t col = 0; col <= SECURITY_PARAM; ++col)
	{
		const vole_block* to_hash = col == 0 ? u : &v[VOLE_COL_BLOCKS * (col - 1)];

		hasher_gfsecpar_state state_secpar;
		hasher_gf64_state state_64;
		hasher_gfsecpar_init_state(&state_secpar, );
		hasher_gf64_init_state(&state_64, );
		// TODO: Get witness size.

		// TODO: Pad at beginning.

		// TODO: Maybe better to chunk the loop by HASHER_GFSECPAR_KEY_POWS.
		for (size_t i = 0; i + sizeof(block_secpar) < VOLE_COL_STRIDE; i += POLY_VEC_LEN * sizeof(block_secpar))
		{
			hasher_gfsecpar_update(&chal.key_secpar, &state_secpar, poly_secpar_load(((unsigned char*) to_hash) + i));
			for (size_t j = 0; j < POLY_VEC_LEN * sizeof(block_secpar); j += POLY_VEC_LEN * 8)
				hasher_gf64_update(&chal.key_64, &state_64, poly64_load(((unsigned char*) to_hash) + i + j));
		}

		// TODO: Handle last, partial block, if it could be present.

		// TODO: Combine elements of vector hash.

		poly_secpar_vec poly_hashes[2];
		poly_hashes[0] = hasher_gfsecpar_final(&state_secpar);
		poly_hashes[1] = poly_secpar_from_64(hasher_gf64_final(&state_64));

		poly_secpar_vec mapped_hashes[2];
		for (size_t i = 0; i < 2; ++i)
			mapped_hashes[i] =
				poly_2secpar_reduce_secpar(poly_2secpar_add(
					poly_secpar_mul(matrix[i][0], poly_hashes[0]),
					poly_secpar_mul(matrix[i][1], poly_hashes[1])));


		poly_secpar_store(, mapped_hashes[0]);
	}
}
#else

void vole_check_sender(
	const vole_block* restrict u, const vole_block* restrict v,
	const unsigned char* restrict challenge, unsigned char* restrict response)
{
}

#endif
