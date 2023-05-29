#include "polynomials.h"
#include "polynomials_impl.h"



extern inline poly1_vec poly1_set_all(uint8_t x);
extern inline poly1_vec poly1_load(unsigned long s, unsigned int bit_offset);
extern inline poly1_vec poly1_load_offset8(const void* s, unsigned int bit_offset);
extern inline poly64_vec poly64_load(const void* s);
extern inline poly128_vec poly128_load(const void* s);
extern inline poly192_vec poly192_load(const void* s);
extern inline poly256_vec poly256_load(const void* s);
extern inline poly320_vec poly320_load(const void* s);
extern inline poly384_vec poly384_load(const void* s);
extern inline poly512_vec poly512_load(const void* s);
extern inline poly64_vec poly64_load_dup(const void* s);
extern inline poly128_vec poly128_load_dup(const void* s);
extern inline poly192_vec poly192_load_dup(const void* s);
extern inline poly256_vec poly256_load_dup(const void* s);
extern inline void poly64_store(void* d, poly64_vec s);
extern inline void poly128_store(void* d, poly128_vec s);
extern inline void poly192_store(void* d, poly192_vec s);
extern inline void poly256_store(void* d, poly256_vec s);
extern inline void poly320_store(void* d, poly320_vec s);
extern inline void poly384_store(void* d, poly384_vec s);
extern inline void poly512_store(void* d, poly512_vec s);
extern inline void poly128_store1(void* d, poly128_vec s);
extern inline void poly192_store1(void* d, poly192_vec s);
extern inline void poly256_store1(void* d, poly256_vec s);
extern inline poly128_vec poly128_from_64(poly64_vec x);
extern inline poly192_vec poly192_from_128(poly128_vec x);
extern inline poly256_vec poly256_from_128(poly128_vec x);
extern inline poly256_vec poly256_from_192(poly192_vec x);
extern inline poly384_vec poly384_from_192(poly192_vec x);
extern inline poly320_vec poly320_from_256(poly256_vec x);
extern inline poly512_vec poly512_from_256(poly256_vec x);
extern inline void add_clmul_block_vectors(clmul_block* x, const clmul_block* y, size_t n);
extern inline poly64_vec poly64_add(poly64_vec x, poly64_vec y);
extern inline poly128_vec poly128_add(poly128_vec x, poly128_vec y);
extern inline poly192_vec poly192_add(poly192_vec x, poly192_vec y);
extern inline poly256_vec poly256_add(poly256_vec x, poly256_vec y);
extern inline poly320_vec poly320_add(poly320_vec x, poly320_vec y);
extern inline poly384_vec poly384_add(poly384_vec x, poly384_vec y);
extern inline poly512_vec poly512_add(poly512_vec x, poly512_vec y);
extern inline poly128_vec poly64_mul(poly64_vec x, poly64_vec y);
extern inline void karatsuba_mul_128_uninterpolated_other_sum(
	poly128_vec x, poly128_vec y, poly128_vec x_for_sum, poly128_vec y_for_sum, poly128_vec* out);
extern inline void karatsuba_mul_128_uninterpolated(poly128_vec x, poly128_vec y, poly128_vec* out);
extern inline void karatsuba_mul_128_uncombined(poly128_vec x, poly128_vec y, poly128_vec* out);
extern inline void combine_poly128s(poly128_vec* out, const poly128_vec* in, size_t n);
extern inline poly256_vec poly128_mul(poly128_vec x, poly128_vec y);
extern inline poly384_vec poly192_mul(poly192_vec x, poly192_vec y);
extern inline poly512_vec poly256_mul(poly256_vec x, poly256_vec y);
extern inline poly192_vec poly64x128_mul(poly64_vec x, poly128_vec y);
extern inline poly256_vec poly64x192_mul(poly64_vec x, poly192_vec y);
extern inline poly320_vec poly64x256_mul(poly64_vec x, poly256_vec y);
extern inline clmul_block poly1_to_bit_mask(poly1_vec x);
extern inline poly128_vec poly1x128_mul(poly1_vec x, poly128_vec y);
extern inline poly192_vec poly1x192_mul(poly1_vec x, poly192_vec y);
extern inline poly256_vec poly1x256_mul(poly1_vec x, poly256_vec y);
extern inline void poly_shift_left_1(clmul_block* x, size_t chunks);
extern inline void poly_shift_left_8(clmul_block* out, const clmul_block* in, size_t chunks);
extern inline poly256_vec poly256_shift_left_1(poly256_vec x);
extern inline poly384_vec poly384_shift_left_1(poly384_vec x);
extern inline poly512_vec poly512_shift_left_1(poly512_vec x);
extern inline poly256_vec poly256_shift_left_8(poly256_vec x);
extern inline poly384_vec poly384_shift_left_8(poly384_vec x);
extern inline poly512_vec poly512_shift_left_8(poly512_vec x);
extern inline poly128_vec poly128_set_low32(uint32_t x);
extern inline poly64_vec poly64_set_low32(uint32_t x);
extern inline poly192_vec poly192_set_low32(uint32_t x);
extern inline poly256_vec poly256_set_low32(uint32_t x);
extern inline poly320_vec poly320_set_low32(uint32_t x);
extern inline poly384_vec poly384_set_low32(uint32_t x);
extern inline poly512_vec poly512_set_low32(uint32_t x);
extern inline poly64_vec poly128_reduce64(poly128_vec x);
extern inline poly64_vec poly64_mul_a64_reduce64(poly64_vec x);
extern inline poly128_vec poly256_reduce128(poly256_vec x);
extern inline poly192_vec poly384_reduce192(poly384_vec x);
extern inline poly256_vec poly512_reduce256(poly512_vec x);
extern inline poly128_vec poly192_reduce128(poly192_vec x);
extern inline poly192_vec poly256_reduce192(poly256_vec x);
extern inline poly256_vec poly320_reduce256(poly320_vec x);
extern inline poly128_vec poly128_from_1(poly1_vec x);
extern inline poly192_vec poly192_from_1(poly1_vec x);
extern inline poly256_vec poly256_from_1(poly1_vec x);
extern inline poly128_vec poly128_from_8_poly1(const poly1_vec* bits);
extern inline poly192_vec poly192_from_8_poly1(const poly1_vec* bits);
extern inline poly256_vec poly256_from_8_poly1(const poly1_vec* bits);
extern inline poly128_vec poly128_from_8_poly128(const poly128_vec* polys);
extern inline poly192_vec poly192_from_8_poly192(const poly192_vec* polys);
extern inline poly256_vec poly256_from_8_poly256(const poly256_vec* polys);
extern inline poly128_vec poly128_from_byte(uint8_t byte);
extern inline poly192_vec poly192_from_byte(uint8_t byte);
extern inline poly256_vec poly256_from_byte(uint8_t byte);
extern inline bool poly64_eq(poly64_vec x, poly64_vec y);
extern inline bool poly128_eq(poly128_vec x, poly128_vec y);
extern inline bool poly192_eq(poly192_vec x, poly192_vec y);
extern inline bool poly256_eq(poly256_vec x, poly256_vec y);
extern inline bool poly320_eq(poly320_vec x, poly320_vec y);
extern inline bool poly384_eq(poly384_vec x, poly384_vec y);
extern inline bool poly512_eq(poly512_vec x, poly512_vec y);
extern inline poly128_vec poly128_extract(poly128_vec x, size_t index);
extern inline poly192_vec poly192_extract(poly192_vec x, size_t index);
extern inline poly256_vec poly256_extract(poly256_vec x, size_t index);
