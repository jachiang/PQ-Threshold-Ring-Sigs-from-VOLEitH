
#include <array>
#include <vector>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "prgs.h"
#include "small_vole.h"
#include "vector_com.h"

}

#include "catch_amalgamated.hpp"


typedef std::array<uint8_t, SECURITY_PARAM / 8> arr_secpar;
typedef std::array<uint8_t, 2 * SECURITY_PARAM / 8> arr_2secpar;


TEST_CASE( "commit/open/verify", "[vector com]" ) {

    block_secpar seed = rand<block_secpar>();
    std::vector<block_secpar> forest(VECTOR_COMMIT_NODES);
    std::vector<block_secpar> leaves_sender(VECTOR_COMMIT_LEAVES);
    std::vector<block_secpar> leaves_receiver(VECTOR_COMMIT_LEAVES);
    std::vector<block_2secpar> hashed_leaves_sender(VECTOR_COMMIT_LEAVES);
    std::vector<block_2secpar> hashed_leaves_receiver(VECTOR_COMMIT_LEAVES);

    const size_t delta = 42 % (1 << VOLE_MIN_K);

    std::vector<uint8_t> delta_bytes(SECURITY_PARAM, 0);
    for (size_t i = 0, dst = 0; i < BITS_PER_WITNESS; ++i)
    {
        size_t k = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
        expand_bits_to_bytes(&delta_bytes[dst], k, delta);
        dst += k;
    }

    std::vector<unsigned char> opening(VECTOR_OPEN_SIZE);

    vector_commit(seed, forest.data(), leaves_sender.data(), hashed_leaves_sender.data());
    vector_open(forest.data(), hashed_leaves_sender.data(), delta_bytes.data(), opening.data());
    vector_verify(opening.data(), delta_bytes.data(), leaves_receiver.data(), hashed_leaves_receiver.data());

    const auto hashed_leaves_sender_bytes = std::vector(reinterpret_cast<arr_2secpar*>(hashed_leaves_sender.data()),
                                                        reinterpret_cast<arr_2secpar*>(hashed_leaves_sender.data() + hashed_leaves_sender.size()));
    const auto hashed_leaves_receiver_bytes = std::vector(reinterpret_cast<arr_2secpar*>(hashed_leaves_receiver.data()),
                                                          reinterpret_cast<arr_2secpar*>(hashed_leaves_receiver.data() + hashed_leaves_receiver.size()));
    REQUIRE( hashed_leaves_receiver_bytes == hashed_leaves_sender_bytes );

    for (size_t i = 0, src = 0; i < BITS_PER_WITNESS; ++i)
    {
        size_t k = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
        for (size_t j = 0; j < (size_t) 1 << k; ++j)
        {
            if (j == delta)
                continue;

            arr_secpar sender_leaf, receiver_leaf;
            memcpy(&sender_leaf, &leaves_sender[src + vole_permute_key_index_inv(j)], sender_leaf.size());
            memcpy(&receiver_leaf, &leaves_receiver[src + vole_permute_key_index_inv(j ^ delta)], receiver_leaf.size());
            INFO(i);
            INFO(j);
            REQUIRE(sender_leaf == receiver_leaf);
        }

        src += (size_t) 1 << k;
    }
}

#if BITS_PER_WITNESS == 32 && SECURITY_PARAM == 128

namespace tv128 {
    // test vectors from faest-ref
    constexpr unsigned int test_vectors = 4;
    constexpr unsigned int depth = 4;
    static_assert(depth == VOLE_MAX_K);

    constexpr std::array<uint8_t, 16> root_key_128{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    // the hashed leaves
    constexpr std::array<uint8_t, 16 * 128 / 8 * 2> com_128{
        0x0f, 0xbc, 0x54, 0x0a, 0xc5, 0x0e, 0xec, 0x23, 0xc7, 0x9d, 0xa9, 0x3a, 0xb9, 0x54, 0xfa,
        0x30, 0xe7, 0x72, 0x6b, 0xa8, 0xa8, 0xc5, 0xfb, 0x6c, 0x7b, 0x84, 0x49, 0xcf, 0x5d, 0xf1,
        0x8d, 0x5a, 0x91, 0x19, 0x5c, 0xd4, 0x4d, 0x2d, 0x78, 0xae, 0xdc, 0x7a, 0x37, 0xe3, 0x98,
        0x69, 0x18, 0x87, 0x4f, 0x44, 0xe4, 0xcf, 0xa1, 0x01, 0x26, 0x37, 0x3e, 0xc8, 0x32, 0xcd,
        0xc2, 0x51, 0xe2, 0x19, 0xc8, 0xe2, 0xa8, 0x1b, 0xc4, 0x0e, 0xeb, 0x69, 0x9e, 0x12, 0x27,
        0x98, 0x87, 0xe4, 0xd0, 0xd0, 0x4e, 0x50, 0x8e, 0x77, 0x0a, 0x2a, 0xc5, 0x39, 0xb7, 0xab,
        0xb8, 0x46, 0x70, 0xa9, 0x3c, 0x10, 0xf5, 0x13, 0x54, 0xf0, 0x37, 0x68, 0xea, 0x61, 0x95,
        0x2a, 0x85, 0xe4, 0x18, 0x99, 0x4b, 0xb7, 0x89, 0x3f, 0x31, 0x0e, 0x7a, 0x17, 0x3b, 0x5e,
        0x87, 0x8c, 0x8d, 0x89, 0x05, 0x97, 0x63, 0x3f, 0x6a, 0x2f, 0x0d, 0x24, 0x01, 0x64, 0xa0,
        0x76, 0xb1, 0x27, 0x26, 0x60, 0x61, 0xe8, 0x75, 0xf7, 0x43, 0x98, 0x0a, 0xed, 0x56, 0xcc,
        0xde, 0xda, 0x76, 0x1b, 0xef, 0xfa, 0xcb, 0xee, 0xd5, 0xb9, 0xb6, 0x27, 0xa2, 0x6e, 0xe0,
        0x62, 0xb4, 0x7c, 0x7f, 0x99, 0x46, 0x42, 0x1f, 0xb7, 0x7c, 0xca, 0x24, 0x3d, 0xc5, 0x06,
        0x30, 0xd9, 0x9e, 0xc8, 0xba, 0xa6, 0xa2, 0x93, 0xaf, 0xf0, 0xc7, 0xb7, 0xd4, 0x88, 0x3f,
        0x95, 0x00, 0xca, 0xca, 0xd7, 0x4c, 0x9e, 0x66, 0xad, 0xa6, 0xc2, 0x8f, 0x7a, 0xfe, 0x7d,
        0x85, 0x83, 0x02, 0x6a, 0x73, 0x88, 0x62, 0xe0, 0x75, 0x8c, 0x1b, 0xf5, 0x90, 0x66, 0xad,
        0xbb, 0xe0, 0x04, 0xef, 0x64, 0x22, 0xa0, 0xcf, 0x3f, 0x7d, 0x21, 0x06, 0x07, 0xc4, 0x08,
        0x2b, 0x11, 0x2a, 0x7b, 0xdd, 0x19, 0xdb, 0x8c, 0xab, 0x6c, 0x9f, 0x50, 0x30, 0x51, 0x2d,
        0xd7, 0x7e, 0x7a, 0xdf, 0x69, 0x5e, 0xbd, 0xba, 0xbf, 0x46, 0x74, 0x76, 0x92, 0xc9, 0xbc,
        0x3d, 0xf2, 0xcb, 0x8d, 0xc8, 0xaf, 0xa4, 0x9e, 0x27, 0xa8, 0x1e, 0x1e, 0x56, 0x36, 0x89,
        0xf1, 0xee, 0x66, 0x88, 0x82, 0xd6, 0x66, 0x8f, 0x65, 0x8b, 0xcc, 0x21, 0x0d, 0xd0, 0xae,
        0x54, 0x7f, 0x13, 0x11, 0x84, 0xfe, 0x5d, 0x2c, 0x6d, 0x19, 0xed, 0x7d, 0xd1, 0x19, 0x1e,
        0x98, 0x38, 0x5c, 0x2c, 0x5d, 0xac, 0x97, 0x6c, 0xab, 0x37, 0xb8, 0x76, 0xe9, 0x8e, 0xbb,
        0xab, 0xa5, 0x73, 0x13, 0xcd, 0xbd, 0x9b, 0x51, 0x07, 0x8e, 0x70, 0x8e, 0xa1, 0xd8, 0x66,
        0xf1, 0xbf, 0x84, 0x1f, 0x38, 0x7a, 0x56, 0x81, 0x2c, 0x75, 0xc7, 0x5a, 0x54, 0x98, 0x4e,
        0x11, 0x03, 0x34, 0xa9, 0x42, 0xa3, 0xda, 0xa5, 0x8a, 0x98, 0x56, 0xe6, 0x86, 0xae, 0x09,
        0x5f, 0xfc, 0x32, 0x24, 0x10, 0x23, 0x49, 0xaa, 0xdc, 0x70, 0x20, 0x56, 0x92, 0x59, 0xdc,
        0xb5, 0x37, 0xaf, 0xf4, 0xb7, 0x09, 0x20, 0x25, 0xdf, 0x0f, 0xdb, 0xa7, 0x42, 0x1f, 0x74,
        0x64, 0xc5, 0x7a, 0x1a, 0xc6, 0xe6, 0x21, 0x8e, 0x98, 0x5e, 0xe2, 0x32, 0xf4, 0x00, 0x06,
        0xb1, 0x68, 0x54, 0xef, 0x6b, 0x5b, 0x14, 0x18, 0x75, 0x85, 0x55, 0x6c, 0xf5, 0x7c, 0x74,
        0xbb, 0x08, 0x42, 0x57, 0xf5, 0x7d, 0xc7, 0x39, 0x44, 0xd1, 0x22, 0xeb, 0xc2, 0xed, 0x7f,
        0x9d, 0xa3, 0x23, 0xb5, 0x4a, 0x04, 0x65, 0x75, 0x93, 0x7c, 0xca, 0xf8, 0xc5, 0x95, 0xaf,
        0x65, 0x7f, 0x44, 0x2c, 0xe7, 0xf5, 0x21, 0x31, 0xc5, 0x36, 0xb3, 0x62, 0x2e, 0x9b, 0xbe,
        0x1c, 0x62, 0x34, 0xfb, 0x52, 0xe8, 0x7e, 0xe0, 0xac, 0x73, 0xfb, 0xe7, 0x10, 0xc8, 0x1c,
        0x66, 0x99, 0x6f, 0x9c, 0x2a, 0xc9, 0xd6, 0xd6, 0x3e, 0x3a, 0x07, 0xf2, 0x3d, 0xd1, 0x95,
        0xc8, 0xe8,
    };
    constexpr std::array<uint8_t, test_vectors * 4 * 128 / 8> pdec_j_128{
        0x73, 0x46, 0x13, 0x95, 0x95, 0xc0, 0xb4, 0x1e, 0x49, 0x7b, 0xbd, 0xe3, 0x65, 0xf4, 0x2d,
        0x0a, 0xb7, 0x5b, 0x1a, 0x66, 0xb8, 0xa4, 0x21, 0x3a, 0xb3, 0xf5, 0xd7, 0x3e, 0x3b, 0xa9,
        0x8a, 0x87, 0x66, 0x80, 0x4f, 0xa3, 0xa1, 0x3a, 0x7e, 0x39, 0x1c, 0xa2, 0xcd, 0xe3, 0x7c,
        0x7c, 0x9e, 0xcf, 0x53, 0x81, 0x5c, 0x98, 0x70, 0xfa, 0xbc, 0xdc, 0xe3, 0x25, 0x1a, 0xe9,
        0xba, 0xa1, 0x0d, 0xdd, 0x73, 0x46, 0x13, 0x95, 0x95, 0xc0, 0xb4, 0x1e, 0x49, 0x7b, 0xbd,
        0xe3, 0x65, 0xf4, 0x2d, 0x0a, 0xb7, 0x5b, 0x1a, 0x66, 0xb8, 0xa4, 0x21, 0x3a, 0xb3, 0xf5,
        0xd7, 0x3e, 0x3b, 0xa9, 0x8a, 0x87, 0x66, 0x80, 0x4f, 0xa3, 0xa1, 0x3a, 0x7e, 0x39, 0x1c,
        0xa2, 0xcd, 0xe3, 0x7c, 0x7c, 0x9e, 0xcf, 0x83, 0x84, 0xe6, 0xcd, 0x73, 0x58, 0x8b, 0xb3,
        0xba, 0x12, 0x0f, 0xb0, 0x86, 0xfe, 0x4c, 0xfc, 0x73, 0x46, 0x13, 0x95, 0x95, 0xc0, 0xb4,
        0x1e, 0x49, 0x7b, 0xbd, 0xe3, 0x65, 0xf4, 0x2d, 0x0a, 0xb7, 0x5b, 0x1a, 0x66, 0xb8, 0xa4,
        0x21, 0x3a, 0xb3, 0xf5, 0xd7, 0x3e, 0x3b, 0xa9, 0x8a, 0x87, 0x7f, 0xd3, 0x3c, 0x93, 0x31,
        0x62, 0x41, 0xbe, 0x4b, 0xe3, 0x3f, 0xa2, 0x1e, 0xb6, 0x64, 0x1c, 0x81, 0x90, 0xd9, 0x7a,
        0x1e, 0xdb, 0x75, 0x95, 0x22, 0x5a, 0x77, 0x00, 0x2d, 0x04, 0xe3, 0x21, 0x73, 0x46, 0x13,
        0x95, 0x95, 0xc0, 0xb4, 0x1e, 0x49, 0x7b, 0xbd, 0xe3, 0x65, 0xf4, 0x2d, 0x0a, 0xb7, 0x5b,
        0x1a, 0x66, 0xb8, 0xa4, 0x21, 0x3a, 0xb3, 0xf5, 0xd7, 0x3e, 0x3b, 0xa9, 0x8a, 0x87, 0x7f,
        0xd3, 0x3c, 0x93, 0x31, 0x62, 0x41, 0xbe, 0x4b, 0xe3, 0x3f, 0xa2, 0x1e, 0xb6, 0x64, 0x1c,
        0xe7, 0x10, 0x19, 0xb7, 0x88, 0x81, 0x34, 0x0c, 0xbf, 0x8e, 0x82, 0x6c, 0x6e, 0xd6, 0x3b,
        0xc5,
    };
    constexpr std::array<uint8_t, test_vectors * 128 / 8 * 2> com_j_128{
        0x0f, 0xbc, 0x54, 0x0a, 0xc5, 0x0e, 0xec, 0x23, 0xc7, 0x9d, 0xa9, 0x3a, 0xb9, 0x54, 0xfa,
        0x30, 0xe7, 0x72, 0x6b, 0xa8, 0xa8, 0xc5, 0xfb, 0x6c, 0x7b, 0x84, 0x49, 0xcf, 0x5d, 0xf1,
        0x8d, 0x5a, 0x91, 0x19, 0x5c, 0xd4, 0x4d, 0x2d, 0x78, 0xae, 0xdc, 0x7a, 0x37, 0xe3, 0x98,
        0x69, 0x18, 0x87, 0x4f, 0x44, 0xe4, 0xcf, 0xa1, 0x01, 0x26, 0x37, 0x3e, 0xc8, 0x32, 0xcd,
        0xc2, 0x51, 0xe2, 0x19, 0xc8, 0xe2, 0xa8, 0x1b, 0xc4, 0x0e, 0xeb, 0x69, 0x9e, 0x12, 0x27,
        0x98, 0x87, 0xe4, 0xd0, 0xd0, 0x4e, 0x50, 0x8e, 0x77, 0x0a, 0x2a, 0xc5, 0x39, 0xb7, 0xab,
        0xb8, 0x46, 0x70, 0xa9, 0x3c, 0x10, 0xf5, 0x13, 0x54, 0xf0, 0x37, 0x68, 0xea, 0x61, 0x95,
        0x2a, 0x85, 0xe4, 0x18, 0x99, 0x4b, 0xb7, 0x89, 0x3f, 0x31, 0x0e, 0x7a, 0x17, 0x3b, 0x5e,
        0x87, 0x8c, 0x8d, 0x89, 0x05, 0x97, 0x63, 0x3f,
    };
}

TEST_CASE( "compare against tv128", "[vec com]" ) {
    std::vector<block_secpar> roots(BITS_PER_WITNESS);
    std::vector<block_secpar> forest(VECTOR_COMMIT_NODES);
    std::vector<block_secpar> leaves_sender(VECTOR_COMMIT_LEAVES);
    std::vector<block_secpar> leaves_receiver(VECTOR_COMMIT_LEAVES);
    std::vector<block_2secpar> hashed_leaves_sender(VECTOR_COMMIT_LEAVES);
    std::vector<block_2secpar> hashed_leaves_receiver(VECTOR_COMMIT_LEAVES);
    std::vector<uint8_t> delta_bytes(SECURITY_PARAM, 0);
    std::vector<uint8_t> opening(VECTOR_OPEN_SIZE);

    // init fixed keys
	block_secpar fixed_key_iv = block_secpar_set_zero();
	prg_tree_fixed_key fixed_key_tree;
	prg_leaf_fixed_key fixed_key_leaf;
	init_fixed_keys(&fixed_key_tree, &fixed_key_leaf, fixed_key_iv);

    // init roots (first from tv, other zero)
    memcpy(&roots[0], tv128::root_key_128.data(), 16);
    for (size_t i = 1; i < BITS_PER_WITNESS; ++i) {
        roots[i] = block_secpar_set_zero();
    }

    // commit
    REQUIRE( tv128::com_128.size() ==
            (hashed_leaves_sender.size() * sizeof(block_2secpar) / BITS_PER_WITNESS) );
    vector_commit_from_roots(roots.data(), forest.data(), leaves_sender.data(),
                             hashed_leaves_sender.data(), &fixed_key_tree, &fixed_key_leaf);
    // check the hashed leaves
    {
        std::array<uint8_t, 2 * SECURITY_PARAM / 8 * (1 << VOLE_MAX_K)> hashed_leaves_vec;
        memcpy(hashed_leaves_vec.data(), hashed_leaves_sender.data(), hashed_leaves_vec.size());
        CHECK( hashed_leaves_vec == tv128::com_128 );
    }


    for (size_t delta = 0; delta < tv128::test_vectors; ++delta) {
        INFO( "delta = " << delta );
        assert(delta < (1 << VOLE_MIN_K));
        for (size_t i = 0, dst = 0; i < BITS_PER_WITNESS; ++i)
        {
            size_t k = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
            expand_bits_to_bytes(&delta_bytes[dst], k, delta);
            dst += k;
        }

        vector_open(forest.data(), hashed_leaves_sender.data(), delta_bytes.data(), opening.data());
        // check the opening
        {
            const size_t PATH_SIZE = SECURITY_PARAM / 8 * VOLE_MAX_K;
            const size_t HASH_SIZE = 2 * SECURITY_PARAM / 8;
            REQUIRE( (PATH_SIZE * tv128::test_vectors) == tv128::pdec_j_128.size() );
            std::array<uint8_t, PATH_SIZE> path_vec;
            std::array<uint8_t, PATH_SIZE> tv_path_vec;
            memcpy(path_vec.data(), opening.data(), PATH_SIZE);
            memcpy(tv_path_vec.data(), tv128::pdec_j_128.data() + delta * PATH_SIZE, PATH_SIZE);
            CHECK( path_vec == tv_path_vec );
            std::array<uint8_t, HASH_SIZE> hash_vec;
            std::array<uint8_t, HASH_SIZE> tv_hash_vec;
            memcpy(hash_vec.data(), opening.data() + PATH_SIZE, HASH_SIZE);
            memcpy(tv_hash_vec.data(), tv128::com_j_128.data() + delta * HASH_SIZE, HASH_SIZE);
            CHECK( hash_vec == tv_hash_vec );
        }

        /// verifying the opening
        vector_verify(opening.data(), delta_bytes.data(), leaves_receiver.data(), hashed_leaves_receiver.data());

        const auto hashed_leaves_sender_bytes = std::vector(reinterpret_cast<arr_2secpar*>(hashed_leaves_sender.data()),
                                                            reinterpret_cast<arr_2secpar*>(hashed_leaves_sender.data() + hashed_leaves_sender.size()));
        const auto hashed_leaves_receiver_bytes = std::vector(reinterpret_cast<arr_2secpar*>(hashed_leaves_receiver.data()),
                                                              reinterpret_cast<arr_2secpar*>(hashed_leaves_receiver.data() + hashed_leaves_receiver.size()));
        REQUIRE( hashed_leaves_receiver_bytes == hashed_leaves_sender_bytes );
    }

    // vector_verify(opening.data(), delta_bytes.data(), leaves_receiver.data(), hashed_leaves_receiver.data());
}

#endif
