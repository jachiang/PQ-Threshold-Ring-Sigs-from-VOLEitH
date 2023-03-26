#include "polynomials.h"

const uint32_t gf64_modulus  = (1 << 4) | (1 << 3) | (1 << 1) | 1;
const uint32_t gf128_modulus = (1 << 7) | (1 << 2) | (1 << 1) | 1;
const uint32_t gf192_modulus = (1 << 7) | (1 << 2) | (1 << 1) | 1;
const uint32_t gf256_modulus = (1 << 10) | (1 << 5) | (1 << 2) | 1;

// TODO: extern inlines
