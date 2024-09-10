#include "config.h"

#if defined(OWF_MQ_2_1) || defined(OWF_MQ_2_8)

#include <array>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "mq.h"

}

#include "catch_amalgamated.hpp"

TEST_CASE("mq multiply") {
    // checked with wolfram
    // ((x^7 + x + 1) * (x^4 + x + 1))  / (x^8 + x^4 + x^3 + x + 1) remainder
    uint8_t x = 0x83;
    uint8_t y = 0x13;
    REQUIRE(mq_2_8_mul(x, y) == 0x76);

    // checked with wolfram
    // ((x^7 + x^5 + x + 1) * (x^7 + x + 1))  / (x^8 + x^4 + x^3 + x + 1) remainder
    x = 0xa3;
    y = 0x83;
    REQUIRE(mq_2_8_mul(x, y) == 0x54);

    printf("\nTESTING MQ-2^8-L1-MUL-FINISHED!\n");

}

#else
typedef int make_iso_compilers_happy;
#endif
