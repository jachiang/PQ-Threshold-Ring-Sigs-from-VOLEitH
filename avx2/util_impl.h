#ifndef UTIL_IMPL_H
#define UTIL_IMPL_H

inline uint64_t tzcnt(uint64_t x)
{
	return _tzcnt_u64(x);
}

#endif
