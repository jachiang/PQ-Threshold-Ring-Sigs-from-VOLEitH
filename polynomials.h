#ifndef POLYNOMIALS_H
#define POLYNOMIALS_H

#include <stdbool.h>
#include <inttypes.h>

#define POLY_VEC_LEN (1 << POLY_VEC_LEN_SHIFT)

// Modulus for GF(2^n), without the x^n term.
extern const uint32_t gf64_modulus;  // degree = 4
extern const uint32_t gf128_modulus; // degree = 7
extern const uint32_t gf192_modulus; // degree = 7
extern const uint32_t gf256_modulus; // degree = 10

#include "polynomials_impl.h"

// Interface defined by polynomials_impl.h:

// typedef /**/ poly1_vec;
// typedef /**/ poly64_vec;
// typedef /**/ poly128_vec;
// typedef /**/ poly192_vec;
// typedef /**/ poly256_vec;
// typedef /**/ poly320_vec;
// typedef /**/ poly384_vec;
// typedef /**/ poly512_vec;
//
// #define AES_PREFERRED_WIDTH_SHIFT /**/
// #define RIJNDAEL256_PREFERRED_WIDTH_SHIFT /**/

// x = 0 for 0, 0xff for 1.
inline poly1_vec poly1_set_all(uint8_t x);

// Load a vector of POLY_VEC_LEN polynomials from a packed format.
inline poly64_vec poly64_load(const void* s);
inline poly128_vec poly128_load(const void* s);
inline poly192_vec poly192_load(const void* s);
inline poly256_vec poly256_load(const void* s);
inline poly320_vec poly320_load(const void* s);
inline poly384_vec poly384_load(const void* s);
inline poly512_vec poly512_load(const void* s);

// Load two consecutive bits from s, starting from offset bit_offset, which should be at most 8.
inline poly1_vec poly1_load(const void* s, unsigned int bit_offset);

// Load two bits with a stride of 8 bits from s, starting from offset bit_offset, which should be at
// most 7.
inline poly1_vec poly1_load_offset8(const void* s, unsigned int bit_offset);

// Load a polynomial from packed format, then duplicate it into all POLY_VEC_LEN indexes.
inline poly64_vec poly64_load_dup(const void* s);
inline poly128_vec poly128_load_dup(const void* s);
inline poly192_vec poly192_load_dup(const void* s);
inline poly256_vec poly256_load_dup(const void* s);

// Set the low 32 bits in all components.
inline poly64_vec poly64_set_low32(uint32_t x);
inline poly128_vec poly128_set_low32(uint32_t x);
inline poly192_vec poly192_set_low32(uint32_t x);
inline poly256_vec poly256_set_low32(uint32_t x);
inline poly320_vec poly320_set_low32(uint32_t x);
inline poly384_vec poly384_set_low32(uint32_t x);
inline poly512_vec poly512_set_low32(uint32_t x);

// Store a vector of POLY_VEC_LEN polynomials in a packed format.
inline void poly64_store(void* d, poly64_vec s);
inline void poly128_store(void* d, poly128_vec s);
inline void poly192_store(void* d, poly192_vec s);
inline void poly256_store(void* d, poly256_vec s);
inline void poly320_store(void* d, poly320_vec s);
inline void poly384_store(void* d, poly384_vec s);
inline void poly512_store(void* d, poly512_vec s);

// Convert a vector of small degree polynomials into a vector larger degree polynomials by setting
// the higher coefficients to zero.
inline poly128_vec poly128_from_64(poly64_vec x);
inline poly192_vec poly192_from_128(poly128_vec x);
inline poly256_vec poly256_from_128(poly128_vec x);
inline poly256_vec poly256_from_192(poly192_vec x);
inline poly384_vec poly384_from_192(poly192_vec x);
inline poly320_vec poly320_from_256(poly256_vec x);
inline poly512_vec poly512_from_256(poly256_vec x);
inline poly128_vec poly128_from_1(poly1_vec x);
inline poly192_vec poly192_from_1(poly1_vec x);
inline poly256_vec poly256_from_1(poly1_vec x);

// Add two vectors of POLY_VEC_LEN polynomials.
inline poly64_vec poly64_add(poly64_vec x, poly64_vec y);
inline poly128_vec poly128_add(poly128_vec x, poly128_vec y);
inline poly192_vec poly192_add(poly192_vec x, poly192_vec y);
inline poly256_vec poly256_add(poly256_vec x, poly256_vec y);
inline poly320_vec poly320_add(poly320_vec x, poly320_vec y);
inline poly384_vec poly384_add(poly384_vec x, poly384_vec y);
inline poly512_vec poly512_add(poly512_vec x, poly512_vec y);

// Multiply two vectors of polynomials, x, componentwise.
inline poly128_vec poly64_mul(poly64_vec x, poly64_vec y);
inline poly256_vec poly128_mul(poly128_vec x, poly128_vec y);
inline poly384_vec poly192_mul(poly192_vec x, poly192_vec y);
inline poly512_vec poly256_mul(poly256_vec x, poly256_vec y);

inline poly192_vec poly64x128_mul(poly64_vec x, poly128_vec y);
inline poly256_vec poly64x192_mul(poly64_vec x, poly192_vec y);
inline poly320_vec poly64x256_mul(poly64_vec x, poly256_vec y);

inline poly128_vec poly1x128_mul(poly1_vec x, poly128_vec y);
inline poly192_vec poly1x192_mul(poly1_vec x, poly192_vec y);
inline poly256_vec poly1x256_mul(poly1_vec x, poly256_vec y);

// Reduce modulo the modulus for GF(2**n).
inline poly64_vec poly128_reduce64(poly128_vec x);
inline poly128_vec poly192_reduce128(poly192_vec x);
inline poly128_vec poly256_reduce128(poly256_vec x);
inline poly192_vec poly256_reduce192(poly256_vec x);
inline poly192_vec poly384_reduce192(poly384_vec x);
inline poly256_vec poly320_reduce256(poly320_vec x);
inline poly256_vec poly512_reduce256(poly512_vec x);

// Multiply by a**64, then reduce modulo the modulus of GF(2**64);
inline poly64_vec poly64_mul_a64_reduce64(poly64_vec x);

// Convert 8 bits into a GF(2^8) element, and embed it into GF(2**n).
inline poly128_vec poly128_from_8_poly1(const poly1_vec* bits);
inline poly192_vec poly192_from_8_poly1(const poly1_vec* bits);
inline poly256_vec poly256_from_8_poly1(const poly1_vec* bits);

// Same linear transformation as poly*_from_8_poly1, but apply it to GF(2**n) elements instead.
inline poly128_vec poly128_from_8_poly128(const poly128_vec* polys);
inline poly192_vec poly192_from_8_poly192(const poly192_vec* polys);
inline poly256_vec poly256_from_8_poly256(const poly256_vec* polys);

// Test two vectors of polynomials for equality
inline bool poly64_eq(poly64_vec x, poly64_vec y);
inline bool poly128_eq(poly128_vec x, poly128_vec y);
inline bool poly192_eq(poly192_vec x, poly192_vec y);
inline bool poly256_eq(poly256_vec x, poly256_vec y);
inline bool poly320_eq(poly320_vec x, poly320_vec y);
inline bool poly384_eq(poly384_vec x, poly384_vec y);
inline bool poly512_eq(poly512_vec x, poly512_vec y);

// Move single polynomial with given index into the first slot of a new vector and zero the other
// components.
inline poly128_vec poly128_extract(poly128_vec x, size_t index);
inline poly192_vec poly192_extract(poly192_vec x, size_t index);
inline poly256_vec poly256_extract(poly256_vec x, size_t index);

#if SECURITY_PARAM == 128
typedef poly128_vec poly_secpar_vec;
typedef poly192_vec poly_secpar_plus_64_vec;
typedef poly256_vec poly_2secpar_vec;

inline poly_secpar_vec poly_secpar_load(const void* s)
{
	return poly128_load(s);
}
inline poly_secpar_vec poly_secpar_load_dup(const void* s)
{
	return poly128_load_dup(s);
}
inline poly_secpar_vec poly_secpar_set_low32(uint32_t x)
{
	return poly128_set_low32(x);
}
inline void poly_secpar_store(void* d, poly_secpar_vec s)
{
	poly128_store(d, s);
}
inline poly_secpar_vec poly_secpar_add(poly_secpar_vec x, poly_secpar_vec y)
{
	return poly128_add(x, y);
}
inline poly_secpar_plus_64_vec poly_secpar_plus_64_add(poly_secpar_plus_64_vec x, poly_secpar_plus_64_vec y)
{
	return poly192_add(x, y);
}
inline poly_2secpar_vec poly_2secpar_add(poly_2secpar_vec x, poly_2secpar_vec y)
{
	return poly256_add(x, y);
}
inline poly_2secpar_vec poly_secpar_mul(poly_secpar_vec x, poly_secpar_vec y)
{
	return poly128_mul(x, y);
}
inline poly_secpar_vec poly1xsecpar_mul(poly1_vec x, poly_secpar_vec y)
{
	return poly1x128_mul(x, y);
}
inline poly_secpar_plus_64_vec poly64xsecpar_mul(poly64_vec x, poly_secpar_vec y)
{
	return poly64x128_mul(x, y);
}
inline poly_secpar_vec poly_2secpar_reduce_secpar(poly_2secpar_vec x)
{
	return poly256_reduce128(x);
}
inline poly_secpar_vec poly_secpar_plus_64_reduce_secpar(poly_secpar_plus_64_vec x)
{
	return poly192_reduce128(x);
}
inline poly_secpar_plus_64_vec poly_secpar_plus_64_from_secpar(poly_secpar_vec x)
{
    return poly192_from_128(x);
}
inline poly_2secpar_vec poly_2secpar_from_secpar(poly_secpar_vec x)
{
    return poly256_from_128(x);
}
inline poly_secpar_vec poly_secpar_extract(poly_secpar_vec x, size_t index)
{
    return poly128_extract(x, index);
}
inline poly_secpar_vec poly_secpar_from_8_poly1(const poly1_vec* bits)
{
	return poly128_from_8_poly1(bits);
}
inline poly_secpar_vec poly_secpar_from_8_poly_secpar(const poly_secpar_vec* polys)
{
	return poly128_from_8_poly128(polys);
}

#elif SECURITY_PARAM == 192
typedef poly192_vec poly_secpar_vec;
typedef poly256_vec poly_secpar_plus_64_vec;
typedef poly384_vec poly_2secpar_vec;

inline poly_secpar_vec poly_secpar_load(const void* s)
{
	return poly192_load(s);
}
inline poly_secpar_vec poly_secpar_load_dup(const void* s)
{
	return poly192_load_dup(s);
}
inline poly_secpar_vec poly_secpar_set_low32(uint32_t x)
{
	return poly192_set_low32(x);
}
inline void poly_secpar_store(void* d, poly_secpar_vec s)
{
	poly192_store(d, s);
}
inline poly_secpar_vec poly_secpar_add(poly_secpar_vec x, poly_secpar_vec y)
{
	return poly192_add(x, y);
}
inline poly_secpar_plus_64_vec poly_secpar_plus_64_add(poly_secpar_plus_64_vec x, poly_secpar_plus_64_vec y)
{
	return poly256_add(x, y);
}
inline poly_2secpar_vec poly_2secpar_add(poly_2secpar_vec x, poly_2secpar_vec y)
{
	return poly384_add(x, y);
}
inline poly_2secpar_vec poly_secpar_mul(poly_secpar_vec x, poly_secpar_vec y)
{
	return poly192_mul(x, y);
}
inline poly_secpar_vec poly1xsecpar_mul(poly1_vec x, poly_secpar_vec y)
{
	return poly1x192_mul(x, y);
}
inline poly_secpar_plus_64_vec poly64xsecpar_mul(poly64_vec x, poly_secpar_vec y)
{
	return poly64x192_mul(x, y);
}
inline poly_secpar_vec poly_2secpar_reduce_secpar(poly_2secpar_vec x)
{
	return poly384_reduce192(x);
}
inline poly_secpar_vec poly_secpar_plus_64_reduce_secpar(poly_secpar_plus_64_vec x)
{
	return poly256_reduce192(x);
}
inline poly_secpar_plus_64_vec poly_secpar_plus_64_from_secpar(poly_secpar_vec x)
{
    return poly256_from_192(x);
}
inline poly_2secpar_vec poly_2secpar_from_secpar(poly_secpar_vec x)
{
    return poly384_from_192(x);
}
inline poly_secpar_vec poly_secpar_extract(poly_secpar_vec x, size_t index)
{
    return poly192_extract(x, index);
}
inline poly_secpar_vec poly_secpar_from_8_poly1(const poly1_vec* bits)
{
	return poly192_from_8_poly1(bits);
}
inline poly_secpar_vec poly_secpar_from_8_poly_secpar(const poly_secpar_vec* polys)
{
	return poly192_from_8_poly192(polys);
}

#elif SECURITY_PARAM == 256
typedef poly256_vec poly_secpar_vec;
typedef poly320_vec poly_secpar_plus_64_vec;
typedef poly512_vec poly_2secpar_vec;

inline poly_secpar_vec poly_secpar_load(const void* s)
{
	return poly256_load(s);
}
inline poly_secpar_vec poly_secpar_load_dup(const void* s)
{
	return poly256_load_dup(s);
}
inline poly_secpar_vec poly_secpar_set_low32(uint32_t x)
{
	return poly256_set_low32(x);
}
inline void poly_secpar_store(void* d, poly_secpar_vec s)
{
	poly256_store(d, s);
}
inline poly_secpar_vec poly_secpar_add(poly_secpar_vec x, poly_secpar_vec y)
{
	return poly256_add(x, y);
}
inline poly_secpar_plus_64_vec poly_secpar_plus_64_add(poly_secpar_plus_64_vec x, poly_secpar_plus_64_vec y)
{
	return poly320_add(x, y);
}
inline poly_2secpar_vec poly_2secpar_add(poly_2secpar_vec x, poly_2secpar_vec y)
{
	return poly512_add(x, y);
}
inline poly_2secpar_vec poly_secpar_mul(poly_secpar_vec x, poly_secpar_vec y)
{
	return poly256_mul(x, y);
}
inline poly_secpar_vec poly1xsecpar_mul(poly1_vec x, poly_secpar_vec y)
{
	return poly1x256_mul(x, y);
}
inline poly_secpar_plus_64_vec poly64xsecpar_mul(poly64_vec x, poly_secpar_vec y)
{
	return poly64x256_mul(x, y);
}
inline poly_secpar_vec poly_2secpar_reduce_secpar(poly_2secpar_vec x)
{
	return poly512_reduce256(x);
}
inline poly_secpar_vec poly_secpar_plus_64_reduce_secpar(poly_secpar_plus_64_vec x)
{
	return poly320_reduce256(x);
}
inline poly_secpar_plus_64_vec poly_secpar_plus_64_from_secpar(poly_secpar_vec x)
{
    return poly320_from_256(x);
}
inline poly_2secpar_vec poly_2secpar_from_secpar(poly_secpar_vec x)
{
    return poly512_from_256(x);
}
inline poly_secpar_vec poly_secpar_extract(poly_secpar_vec x, size_t index)
{
    return poly256_extract(x, index);
}
inline poly_secpar_vec poly_secpar_from_8_poly1(const poly1_vec* bits)
{
	return poly256_from_8_poly1(bits);
}
inline poly_secpar_vec poly_secpar_from_8_poly_secpar(const poly_secpar_vec* polys)
{
	return poly256_from_8_poly256(polys);
}

#endif

#endif
