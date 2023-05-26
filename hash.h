#ifndef HASH_H
#define HASH_H

#include <inttypes.h>
#include <stddef.h>
#include "config.h"

#include "KeccakHash.h"
#include "KeccakHashtimes4.h"

// TODO: Is the error checking really needed?
// Either add it to hash_state_x4, or remove it from hash_state.

typedef Keccak_HashInstance hash_state;

inline int hash_init(hash_state* ctx)
{
#if SECURITY_PARAM <= 128
	return Keccak_HashInitialize_SHAKE128(ctx);
#else
	return Keccak_HashInitialize_SHAKE256(ctx);
#endif
}

inline int hash_update(hash_state* ctx, const uint8_t* input, size_t bytes)
{
	return Keccak_HashUpdate(ctx, input, bytes * 8);
}

inline int hash_final(hash_state* ctx, uint8_t* digest, size_t bytes)
{
	int ret = Keccak_HashFinal(ctx, NULL);
	if (ret != KECCAK_SUCCESS)
		return ret;
	return Keccak_HashSqueeze(ctx, digest, bytes * 8);
}

// Mostly copied from Picnic: Instances that work with 4 states in parallel.
typedef Keccak_HashInstancetimes4 hash_state_x4;

inline void hash_init_x4(hash_state_x4* ctx, size_t digest_size)
{
#if SECURITY_PARAM <= 128
	Keccak_HashInitializetimes4_SHAKE128(ctx);
#else
	Keccak_HashInitializetimes4_SHAKE256(ctx);
#endif
}

inline void hash_update_x4(hash_state_x4* ctx, const uint8_t** data, size_t size)
{
	Keccak_HashUpdatetimes4(ctx, data, size << 3);
}

inline void hash_update_x4_4(hash_state_x4* ctx,
                             const uint8_t* data0, const uint8_t* data1,
                             const uint8_t* data2, const uint8_t* data3, size_t size)
{
	const uint8_t* data[4] = {data0, data1, data2, data3};
	hash_update_x4(ctx, data, size);
}

inline void hash_update_x4_1(hash_state_x4* ctx, const uint8_t* data, size_t size)
{
	const uint8_t* tmp[4] = {data, data, data, data};
	hash_update_x4(ctx, tmp, size);
}

inline void hash_init_prefix_x4(hash_state_x4* ctx, size_t digest_size, const uint8_t prefix)
{
	hash_init_x4(ctx, digest_size);
	hash_update_x4_1(ctx, &prefix, sizeof(prefix));
}

inline void hash_final_x4(hash_state_x4* ctx, uint8_t** buffer, size_t buflen)
{
	Keccak_HashFinaltimes4(ctx, NULL);
	Keccak_HashSqueezetimes4(ctx, buffer, buflen << 3);
}

inline void hash_final_x4_4(hash_state_x4* ctx,
                            uint8_t* buffer0, uint8_t* buffer1, uint8_t* buffer2, uint8_t* buffer3,
                            size_t buflen)
{
	uint8_t* buffer[4] = {buffer0, buffer1, buffer2, buffer3};
	hash_final_x4(ctx, buffer, buflen);
}

#endif
