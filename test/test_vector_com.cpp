
#include <array>
#include <vector>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "vector_com.h"
#include "small_vole.h"

}

#include "catch_amalgamated.hpp"



TEST_CASE( "commit/open/verify", "[vector com]" ) {
    typedef std::array<uint8_t, SECURITY_PARAM / 8> arr_secpar;
    typedef std::array<uint8_t, 2 * SECURITY_PARAM / 8> arr_2secpar;

    std::vector<block_secpar> roots = random_vector<block_secpar>(2 * BITS_PER_WITNESS);
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

    vector_commit(roots.data(), NULL, NULL, forest.data(), leaves_sender.data(), hashed_leaves_sender.data());
    vector_open(forest.data(), hashed_leaves_sender.data(), delta_bytes.data(), opening.data());
    vector_verify(opening.data(), NULL, NULL, delta_bytes.data(), leaves_receiver.data(), hashed_leaves_receiver.data());

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
