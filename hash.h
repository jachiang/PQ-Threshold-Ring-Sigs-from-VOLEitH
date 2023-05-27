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

inline int hash_update(hash_state* ctx, const void* input, size_t bytes)
{
	return Keccak_HashUpdate(ctx, input, bytes * 8);
}

inline int hash_final(hash_state* ctx, void* digest, size_t bytes)
{
	int ret = Keccak_HashFinal(ctx, NULL);
	if (ret != KECCAK_SUCCESS)
		return ret;
	return Keccak_HashSqueeze(ctx, digest, bytes * 8);
}

// Mostly copied from Picnic: Instances that work with 4 states in parallel.
typedef Keccak_HashInstancetimes4 hash_state_x4;

inline void hash_init_x4(hash_state_x4* ctx)
{
#if SECURITY_PARAM <= 128
	Keccak_HashInitializetimes4_SHAKE128(ctx);
#else
	Keccak_HashInitializetimes4_SHAKE256(ctx);
#endif
}

inline void hash_update_x4(hash_state_x4* ctx, const void** data, size_t size)
{
	const uint8_t* data_casted[4] = {data[0], data[1], data[2], data[3]};
	Keccak_HashUpdatetimes4(ctx, data_casted, size << 3);
}

inline void hash_update_x4_4(
	hash_state_x4* ctx,
	const void* data0, const void* data1, const void* data2, const void* data3, size_t size)
{
	const uint8_t* data[4] = {data0, data1, data2, data3};
	Keccak_HashUpdatetimes4(ctx, data, size << 3);
}

inline void hash_update_x4_1(hash_state_x4* ctx, const void* data, size_t size)
{
	const void* tmp[4] = {data, data, data, data};
	hash_update_x4(ctx, tmp, size);
}

inline void hash_init_prefix_x4(hash_state_x4* ctx, const uint8_t prefix)
{
	hash_init_x4(ctx);
	hash_update_x4_1(ctx, &prefix, sizeof(prefix));
}

inline void hash_final_x4(hash_state_x4* ctx, void** buffer, size_t buflen)
{
	uint8_t* buffer_casted[4] = {buffer[0], buffer[1], buffer[2], buffer[3]};
	Keccak_HashFinaltimes4(ctx, NULL);
	Keccak_HashSqueezetimes4(ctx, buffer_casted, buflen << 3);
}

inline void hash_final_x4_4(
	hash_state_x4* ctx, void* buffer0, void* buffer1, void* buffer2, void* buffer3, size_t buflen)
{
	void* buffer[4] = {buffer0, buffer1, buffer2, buffer3};
	hash_final_x4(ctx, buffer, buflen);
}

#endif
