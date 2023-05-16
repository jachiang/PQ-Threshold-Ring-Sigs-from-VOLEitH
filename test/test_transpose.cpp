#include <array>

#include "test.hpp"

extern "C" {

#include "transpose.h"

}

#include "catch_amalgamated.hpp"


const std::array<uint32_t, 16> transpose4x4_32_in = {
    0x00000000, 0x11111111, 0x22222222, 0x33333333,
    0x44444444, 0x55555555, 0x66666666, 0x77777777,
    0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb,
    0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff,
};
const std::array<uint32_t, 16> transpose4x4_32_out = {
    0x00000000, 0x44444444, 0x88888888, 0xcccccccc,
    0x11111111, 0x55555555, 0x99999999, 0xdddddddd,
    0x22222222, 0x66666666, 0xaaaaaaaa, 0xeeeeeeee,
    0x33333333, 0x77777777, 0xbbbbbbbb, 0xffffffff,
};

const std::array<uint32_t, 8> transpose4x2_32_in = {
    0x00000000, 0x11111111,
    0x22222222, 0x33333333,
    0x44444444, 0x55555555,
    0x66666666, 0x77777777,
};
const std::array<uint32_t, 8> transpose4x2_32_out = {
    0x00000000, 0x22222222, 0x44444444, 0x66666666,
    0x11111111, 0x33333333, 0x55555555, 0x77777777,
};

const std::array<uint64_t, 4> transpose2x2_64_in = {
    0x0000000000000000, 0x1111111111111111,
    0x2222222222222222, 0x3333333333333333,
};
const std::array<uint64_t, 4> transpose2x2_64_out = {
    0x0000000000000000, 0x2222222222222222,
    0x1111111111111111, 0x3333333333333333,
};

const std::array<block128, 4> transpose2x2_128_in = {
    _mm_set_epi64x(0x0000000000000000, 0x0000000000000000),
    _mm_set_epi64x(0x1111111111111111, 0x1111111111111111),
    _mm_set_epi64x(0x2222222222222222, 0x2222222222222222),
    _mm_set_epi64x(0x3333333333333333, 0x3333333333333333),
};
const std::array<block128, 4> transpose2x2_128_out = {
    _mm_set_epi64x(0x0000000000000000, 0x0000000000000000),
    _mm_set_epi64x(0x2222222222222222, 0x2222222222222222),
    _mm_set_epi64x(0x1111111111111111, 0x1111111111111111),
    _mm_set_epi64x(0x3333333333333333, 0x3333333333333333),
};


TEST_CASE( "transpose 4x4 32", "[transpose]" ) {
    std::array<block128, 4> in;
    std::array<block128, 4> out;
    std::array<uint32_t, 16> out_32;
    memcpy(in.data(), transpose4x4_32_in.data(), sizeof(in));
    transpose4x4_32(out.data(), in.data());
    memcpy(out_32.data(), out.data(), sizeof(out_32));
    REQUIRE( out_32 == transpose4x4_32_out );
}

TEST_CASE( "transpose 4x2 32", "[transpose]" ) {
    std::array<block128, 2> in;
    std::array<block128, 2> out;
    std::array<uint32_t, 8> out_32;
    memcpy(in.data(), transpose4x2_32_in.data(), sizeof(in));
    transpose4x2_32(out.data(), in[0], in[1]);
    memcpy(out_32.data(), out.data(), sizeof(out_32));
    REQUIRE( out_32 == transpose4x2_32_out );
}

TEST_CASE( "transpose 2x2 64", "[transpose]" ) {
    block256 in;
    std::array<uint64_t, 4> out_64;
    memcpy(&in, transpose2x2_64_in.data(), sizeof(in));
    block256 out = transpose2x2_64(in);
    memcpy(out_64.data(), &out, sizeof(out_64));
    REQUIRE( out_64 == transpose2x2_64_out );
}

TEST_CASE( "transpose 2x2 128", "[transpose]" ) {
    std::array<block256, 2> in;
    std::array<block256, 2> out;
    memcpy(in.data(), transpose2x2_128_in.data(), sizeof(in));
    transpose2x2_128(out.data(), in[0], in[1]);
    REQUIRE( memcmp(&out, &transpose2x2_128_out, sizeof(transpose2x2_128_out)) == 0 );
}
