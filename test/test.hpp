#ifndef TEST_TEST_HPP
#define TEST_TEST_HPP

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "polynomials.h"
}

inline std::string poly_vec_to_string(const uint8_t* buf, size_t poly_size) {
    std::stringstream ss;
    ss << std::hex << "(0x";
    for (size_t i = 0; i < poly_size; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (unsigned) buf[poly_size - i - 1];
    }
    for (size_t j = 1; j < POLY_VEC_LEN; ++j) {
        ss << ", 0x";
        for (size_t i = 0; i < poly_size; ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2) << (unsigned) buf[(j + 1) * poly_size - i - 1];
        }
    }
    ss << ")";
    return ss.str();
}

inline std::string poly64_vec_to_string(poly64_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 8> buf;
    poly64_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 8);
}

inline std::string poly128_vec_to_string(poly128_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 16> buf;
    poly128_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 16);
}

inline std::string poly192_vec_to_string(poly192_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 24> buf;
    poly192_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 24);
}

inline std::string poly256_vec_to_string(poly256_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 32> buf;
    poly256_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 32);
}

inline std::string poly320_vec_to_string(poly320_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 40> buf;
    poly320_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 40);
}

inline std::string poly384_vec_to_string(poly384_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 48> buf;
    poly384_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 48);
}

inline std::string poly512_vec_to_string(poly512_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 64> buf;
    poly512_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 64);
}

#define REQUIRE_POLY64VEC_EQ(a, b) \
    { INFO("Requiring: " << poly64_vec_to_string(a) << " == " << poly64_vec_to_string(b)); REQUIRE(poly64_eq(a, b)); }
#define REQUIRE_POLY64VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly64_vec_to_string(a) << " != " << poly64_vec_to_string(b)); REQUIRE(!poly64_eq(a, b)); }
#define REQUIRE_POLY128VEC_EQ(a, b) \
    { INFO("Requiring: " << poly128_vec_to_string(a) << " == " << poly128_vec_to_string(b)); REQUIRE(poly128_eq(a, b)); }
#define REQUIRE_POLY128VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly128_vec_to_string(a) << " != " << poly128_vec_to_string(b)); REQUIRE(!poly128_eq(a, b)); }
#define REQUIRE_POLY192VEC_EQ(a, b) \
    { INFO("Requiring: " << poly192_vec_to_string(a) << " == " << poly192_vec_to_string(b)); REQUIRE(poly192_eq(a, b)); }
#define REQUIRE_POLY192VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly192_vec_to_string(a) << " != " << poly192_vec_to_string(b)); REQUIRE(!poly192_eq(a, b)); }
#define REQUIRE_POLY256VEC_EQ(a, b) \
    { INFO("Requiring: " << poly256_vec_to_string(a) << " == " << poly256_vec_to_string(b)); REQUIRE(poly256_eq(a, b)); }
#define REQUIRE_POLY256VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly256_vec_to_string(a) << " != " << poly256_vec_to_string(b)); REQUIRE(!poly256_eq(a, b)); }
#define REQUIRE_POLY320VEC_EQ(a, b) \
    { INFO("Requiring: " << poly320_vec_to_string(a) << " == " << poly320_vec_to_string(b)); REQUIRE(poly320_eq(a, b)); }
#define REQUIRE_POLY320VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly320_vec_to_string(a) << " != " << poly320_vec_to_string(b)); REQUIRE(!poly320_eq(a, b)); }
#define REQUIRE_POLY384VEC_EQ(a, b) \
    { INFO("Requiring: " << poly384_vec_to_string(a) << " == " << poly384_vec_to_string(b)); REQUIRE(poly384_eq(a, b)); }
#define REQUIRE_POLY384VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly384_vec_to_string(a) << " != " << poly384_vec_to_string(b)); REQUIRE(!poly384_eq(a, b)); }
#define REQUIRE_POLY512VEC_EQ(a, b) \
    { INFO("Requiring: " << poly512_vec_to_string(a) << " == " << poly512_vec_to_string(b)); REQUIRE(poly512_eq(a, b)); }
#define REQUIRE_POLY512VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly512_vec_to_string(a) << " != " << poly512_vec_to_string(b)); REQUIRE(!poly512_eq(a, b)); }

inline std::ostream& operator<<(std::ostream& o, const std::vector<uint8_t>& array)
{
	o << "{ ";
	for (size_t i = 0; i < array.size(); ++i)
	{
		if (i)
			o << ", ";
		o << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int) array[i];
	}
	return o << " }";
}

template<size_t N>
inline std::ostream& operator<<(std::ostream& o, const std::array<uint8_t, N>& array)
{
	return o << std::vector(array.begin(), array.end());
}

template <typename T>
inline T rand() {
    std::random_device rd("/dev/urandom");
    std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
    return dist(rd);
}

template <typename T>
inline std::vector<T> random_vector(std::size_t size) {
    std::vector<T> v(size);
    std::generate(v.begin(), v.end(), rand<T>);
    return v;
}

#endif
