#ifndef UTIL_H
#define UTIL_H

#include <inttypes.h>

#if defined(__GNUC__)
#define ALWAYS_INLINE inline __attribute__ ((__always_inline__))
#elif defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE inline
#endif

#include "util_impl.h"

// Interface defined by util_impl.h

inline uint64_t tzcnt(uint64_t x);

#endif
