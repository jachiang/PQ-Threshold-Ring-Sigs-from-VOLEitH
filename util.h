#ifndef UTIL_H
#define UTIL_H

#include <inttypes.h>

#ifdef _MSC_VER
#include "intrin.h"
#endif

#if defined(__GNUC__)
#define ALWAYS_INLINE inline __attribute__ ((__always_inline__))
#elif defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE inline
#endif

inline unsigned int count_trailing_zeros(uint64_t x)
{
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_ctzll(x);
#elif defined(_MSC_VER)
	unsigned long result;
	_BitScanForward64(&result, x);
	return result;
#endif

	for (unsigned int i = 0; i < 64; ++i, x >>= 1)
		if (x & 1)
			return i;
	return 64;
}

#endif
