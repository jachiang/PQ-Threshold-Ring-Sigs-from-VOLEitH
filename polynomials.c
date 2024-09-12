#include "polynomials.h"

const uint32_t gf64_modulus  = (1 << 4) | (1 << 3) | (1 << 1) | 1;
const uint32_t gf128_modulus = (1 << 7) | (1 << 2) | (1 << 1) | 1;
const uint32_t gf192_modulus = (1 << 7) | (1 << 2) | (1 << 1) | 1;
const uint32_t gf256_modulus = (1 << 10) | (1 << 5) | (1 << 2) | 1;

const unsigned char gf8_in_gf128[7][16] = {
	{0x0d, 0xce, 0x60, 0x55, 0xac, 0xe8, 0x3f, 0xa1, 0x1c, 0x9a, 0x97, 0xa9, 0x55, 0x85, 0x3d, 0x05},
	{0xe1, 0xae, 0x88, 0x34, 0xca, 0x59, 0x77, 0xec, 0x84, 0xbb, 0xbf, 0x9c, 0x43, 0xb7, 0xf4, 0x4c},
	{0xa8, 0x46, 0x39, 0x36, 0xae, 0x02, 0xcf, 0xbf, 0xc6, 0xd2, 0x51, 0x7d, 0x4f, 0x60, 0xad, 0x35},
	{0x49, 0x98, 0x2e, 0x3c, 0x48, 0x30, 0x83, 0x6b, 0xfe, 0x22, 0xa2, 0x40, 0x46, 0x36, 0xcb, 0x0d},
	{0xb4, 0x82, 0x1b, 0x7b, 0x27, 0x49, 0x2b, 0x25, 0xa5, 0xde, 0x88, 0x1a, 0xe1, 0x10, 0x98, 0x54},
	{0x22, 0xff, 0x21, 0x25, 0xef, 0xf2, 0x2b, 0xc7, 0x75, 0x1f, 0x0c, 0x6c, 0x68, 0xa5, 0x81, 0xd6},
	{0xbc, 0xf9, 0x36, 0xe1, 0x94, 0x8e, 0x7a, 0x7a, 0xe0, 0x8f, 0xb7, 0x4f, 0x1a, 0x31, 0x50, 0x09}
};

const unsigned char gf8_in_gf192[7][24] = {
	{0x63, 0x97, 0x38, 0x6f, 0xd5, 0xa3, 0xc8, 0xcc, 0xea, 0xbd, 0x6e, 0x96, 0x6c, 0xd7, 0x65, 0xe6, 0x62, 0x36, 0x6b, 0x0e, 0x14, 0xc8, 0x0b, 0x31},
	{0xbb, 0x50, 0xf4, 0x7c, 0x9e, 0x61, 0x33, 0xb2, 0x26, 0x3f, 0x63, 0xd5, 0x19, 0x1f, 0xf6, 0x7b, 0x34, 0xdb, 0x91, 0xd4, 0x26, 0x37, 0x93, 0xda},
	{0x0d, 0x8a, 0x39, 0xf5, 0x13, 0x2c, 0x6d, 0x9c, 0x19, 0x8d, 0x32, 0x06, 0x77, 0xe3, 0x32, 0x82, 0xf6, 0x4e, 0x75, 0x3c, 0x70, 0x0d, 0x3b, 0x0c},
	{0x5d, 0xf7, 0x2b, 0xbd, 0x7c, 0x74, 0x20, 0xdd, 0x2e, 0xd2, 0x58, 0x00, 0xab, 0x42, 0x55, 0x7a, 0x51, 0x12, 0xbc, 0x94, 0x9c, 0x51, 0xec, 0x45},
	{0xf8, 0x2b, 0xce, 0x8a, 0xe2, 0x0c, 0xd5, 0xd8, 0x84, 0xbe, 0xde, 0x67, 0xb7, 0x8c, 0x16, 0x08, 0x45, 0x70, 0xa6, 0x4b, 0x6a, 0x14, 0x7d, 0xd6},
	{0xba, 0xe1, 0xd5, 0xee, 0x76, 0x9c, 0x0f, 0x97, 0x48, 0x20, 0xd7, 0x5f, 0xae, 0xf7, 0xea, 0xf3, 0x43, 0xea, 0x6c, 0x69, 0x5f, 0xbd, 0xa6, 0x29},
	{0x71, 0x85, 0x06, 0x65, 0xc2, 0x5d, 0x94, 0xf5, 0xd3, 0xe9, 0x06, 0x39, 0x62, 0xfd, 0x19, 0x60, 0xb0, 0xc4, 0x87, 0x0f, 0x54, 0x56, 0x7c, 0xc7}
};

const unsigned char gf8_in_gf256[7][32] = {
	{0xe7, 0xfe, 0xde, 0x0b, 0x42, 0x88, 0x97, 0x96, 0x67, 0x4e, 0x47, 0xa0, 0x38, 0x8d, 0xd6, 0xbe, 0x6a, 0xe1, 0xf1, 0xf8, 0x45, 0x98, 0x22, 0xdf, 0x33, 0x58, 0xc9, 0x20, 0xcf, 0xa8, 0xc9, 0x04},
	{0xc1, 0x89, 0x22, 0xd5, 0x2a, 0xf5, 0x5a, 0xa9, 0x2f, 0x07, 0x42, 0x2c, 0x8d, 0xc4, 0xa5, 0x2b, 0xea, 0xb0, 0x00, 0x6c, 0x37, 0x0d, 0x4a, 0xd1, 0xf1, 0x4a, 0x5b, 0x9c, 0x69, 0x4d, 0x4e, 0x06},
	{0x1d, 0x9d, 0x80, 0x3f, 0x83, 0xb3, 0xda, 0x55, 0x57, 0x0f, 0x3b, 0x53, 0x1e, 0x83, 0x71, 0x17, 0x10, 0xac, 0x3f, 0xad, 0x3f, 0x57, 0x96, 0xfb, 0x8d, 0xf6, 0x11, 0x70, 0xdb, 0xe3, 0x95, 0x61},
	{0xd5, 0xcd, 0x1b, 0xb0, 0x19, 0x05, 0x01, 0xde, 0xf6, 0xe3, 0x30, 0x1a, 0x91, 0x58, 0x27, 0x75, 0x3f, 0xa0, 0x9e, 0x48, 0xb6, 0x78, 0x07, 0x2a, 0x38, 0x88, 0x76, 0x4f, 0xd6, 0x4f, 0xc2, 0x56},
	{0xb6, 0x30, 0x8a, 0xe9, 0x29, 0xf5, 0xc2, 0x98, 0x82, 0x84, 0xf1, 0x40, 0xd4, 0xdb, 0xc4, 0x1b, 0x81, 0xa9, 0x49, 0x7d, 0x94, 0x09, 0xbe, 0x2f, 0xfc, 0x4f, 0x57, 0x71, 0x6d, 0x0b, 0x27, 0x22},
	{0x0b, 0x67, 0x44, 0xde, 0xb9, 0xaf, 0x75, 0x9e, 0xbc, 0xaf, 0xf1, 0x66, 0xc6, 0x66, 0xed, 0xac, 0x7e, 0x1f, 0x99, 0xf2, 0x3f, 0x25, 0x01, 0xf0, 0xf3, 0x29, 0xfa, 0xd1, 0x2f, 0x37, 0x3d, 0xc0},
	{0x8b, 0xe8, 0x32, 0xb3, 0x98, 0xb6, 0x43, 0xba, 0x0d, 0x6f, 0xb8, 0x25, 0xd6, 0xc4, 0x37, 0x52, 0x45, 0x15, 0xe8, 0xf4, 0x2a, 0x2b, 0x65, 0x2f, 0xb8, 0x7b, 0x6b, 0xd2, 0x09, 0xea, 0x3e, 0x13}
};

extern inline poly_secpar_vec poly_secpar_load(const void* s);
extern inline poly_secpar_vec poly_secpar_load_dup(const void* s);
extern inline poly_secpar_vec poly_secpar_set_zero();
extern inline poly_2secpar_vec poly_2secpar_set_zero();
extern inline poly_secpar_vec poly_secpar_from_1(poly1_vec x);
extern inline poly_secpar_vec poly_secpar_set_low32(uint32_t x);
extern inline void poly_secpar_store(void* d, poly_secpar_vec s);
extern inline void poly_secpar_store1(void* d, poly_secpar_vec s);
extern inline poly_secpar_vec poly_secpar_add(poly_secpar_vec x, poly_secpar_vec y);
extern inline poly_secpar_plus_64_vec poly_secpar_plus_64_add(poly_secpar_plus_64_vec x, poly_secpar_plus_64_vec y);
extern inline poly_2secpar_vec poly_2secpar_add(poly_2secpar_vec x, poly_2secpar_vec y);
extern inline poly_2secpar_vec poly_secpar_mul(poly_secpar_vec x, poly_secpar_vec y);
extern inline poly_secpar_vec poly1xsecpar_mul(poly1_vec x, poly_secpar_vec y);
extern inline poly_secpar_plus_64_vec poly64xsecpar_mul(poly64_vec x, poly_secpar_vec y);
extern inline poly_2secpar_vec poly_2secpar_shift_left_1(poly_2secpar_vec x);
extern inline poly_2secpar_vec poly_2secpar_shift_left_8(poly_2secpar_vec x);
extern inline poly_secpar_vec poly_2secpar_reduce_secpar(poly_2secpar_vec x);
extern inline poly_secpar_vec poly_secpar_plus_64_reduce_secpar(poly_secpar_plus_64_vec x);
extern inline poly_secpar_plus_64_vec poly_secpar_plus_64_from_secpar(poly_secpar_vec x);
extern inline poly_2secpar_vec poly_2secpar_from_secpar(poly_secpar_vec x);
extern inline poly_secpar_vec poly_secpar_from_64(poly64_vec x);
extern inline bool poly_secpar_eq(poly_secpar_vec x, poly_secpar_vec y);
extern inline poly_secpar_vec poly_secpar_extract(poly_secpar_vec x, size_t index);
extern inline poly_2secpar_vec poly_2secpar_extract(poly_2secpar_vec x, size_t index);
extern inline poly_secpar_vec poly_secpar_from_byte(uint8_t byte);
extern inline poly_secpar_vec poly_secpar_from_8_poly1(const poly1_vec* bits);
extern inline poly_secpar_vec poly_secpar_from_8_poly_secpar(const poly_secpar_vec* polys);
extern inline poly_secpar_vec poly_secpar_exp(poly_secpar_vec base, size_t power);

#define DEFINE_POLY_EXP(n, n2) \
	poly##n##_vec poly##n##_exp(poly##n##_vec base, size_t power) \
	{ \
		poly##n##_vec base_exp_pow2 = base; \
		poly##n##_vec base_exp = poly##n##_set_low32(1); \
		bool first = true; \
		for (size_t i = 1; i <= power; i <<= 1) \
		{ \
			if (power & i) \
			{ \
				if (first) \
				{ \
					base_exp = base_exp_pow2; \
					first = false; \
				} \
				else \
					base_exp = poly##n2##_reduce##n(poly##n##_mul(base_exp, base_exp_pow2)); \
			} \
 \
			if ((i << 1) <= power) \
				base_exp_pow2 = poly##n2##_reduce##n(poly##n##_mul(base_exp_pow2, base_exp_pow2)); \
		} \
		return base_exp; \
	}

DEFINE_POLY_EXP(64, 128)
DEFINE_POLY_EXP(128, 256)
DEFINE_POLY_EXP(192, 384)
DEFINE_POLY_EXP(256, 512)
