#ifndef UTIL_H
#define UTIL_H

#if defined(__GNUC__)
#define ALWAYS_INLINE inline __attribute__ ((__always_inline__))
#elif defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE inline
#endif

#endif
