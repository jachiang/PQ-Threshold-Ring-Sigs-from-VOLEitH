#ifndef POLYNOMIALS_H
#define POLYNOMIALS_H

#define POLY_VEC_LEN (1 << POLY_VEC_LEN_SHIFT)

#include "polynomials_impl.h"

// Interface defined by polynomials_impl.h:

// typedef /**/ poly64_vec;
// typedef /**/ poly128_vec;
// typedef /**/ poly256_vec;
// typedef /**/ poly512_vec;
//
// #define AES_PREFERRED_WIDTH_SHIFT /**/
// #define RIJNDAEL256_PREFERRED_WIDTH_SHIFT /**/

// Load a vector of POLY_VEC_LEN polynomials from a packed format.
inline poly64_vec poly64_vec_load(const void* s);
inline poly128_vec poly128_vec_load(const void* s);
inline poly256_vec poly256_vec_load(const void* s);
inline poly512_vec poly512_vec_load(const void* s);

// Store a vector of POLY_VEC_LEN polynomials in a packed format.
inline void poly64_vec_store(void* d, poly64_vec s);
inline void poly128_vec_store(void* d, poly128_vec s);
inline void poly256_vec_store(void* d, poly256_vec s);
inline void poly512_vec_store(void* d, poly512_vec s);

// Add two vectors of POLY_VEC_LEN polynomials.
inline poly64_vec poly64_vec_add(poly64_vec x, poly64_vec y);
inline poly128_vec poly128_vec_add(poly128_vec x, poly128_vec y);
inline poly256_vec poly256_vec_add(poly256_vec x, poly256_vec y);
inline poly512_vec poly512_vec_add(poly512_vec x, poly512_vec y);

// Multiply two vectors of polynomials, componentwise.
inline poly128_vec poly64_vec_mul(poly64_vec x, poly64_vec y);
inline poly256_vec poly128_vec_mul(poly128_vec x, poly128_vec y);
inline poly512_vec poly256_vec_mul(poly256_vec x, poly256_vec y);

// Modulus for GF(2^n), without the x^n term.
inline poly64_vec get_gf64_modulus();
inline poly128_vec get_gf128_modulus();
inline poly256_vec get_gf256_modulus();

// Reduce modulo the modulus for GF(2**n).
inline poly64_vec poly128_vec_reduce64(poly128_vec x);
inline poly128_vec poly256_vec_reduce128(poly256_vec x);
inline poly256_vec poly512_vec_reduce256(poly512_vec x);

#endif
