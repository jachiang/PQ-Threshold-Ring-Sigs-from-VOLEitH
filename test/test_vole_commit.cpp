#include <array>
#include <vector>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "vole_commit.h"
// #include "vector_com.h"
// #include "small_vole.h"

}

#include "catch_amalgamated.hpp"



TEST_CASE( "commit/open/verify", "[vole commit]" ) {
    block_secpar seed = rand<block_secpar>();
    std::vector<block_secpar> forest(VECTOR_COMMIT_NODES);
    std::vector<block_secpar> leaves_sender(VECTOR_COMMIT_LEAVES);
    std::vector<block_secpar> leaves_receiver(VECTOR_COMMIT_LEAVES);
    std::vector<block_2secpar> hashed_leaves_sender(VECTOR_COMMIT_LEAVES);
    std::vector<block_2secpar> hashed_leaves_receiver(VECTOR_COMMIT_LEAVES);

    std::vector<vole_block> u(VOLE_COL_BLOCKS);
    std::vector<vole_block> v(SECURITY_PARAM * VOLE_COL_BLOCKS);
    std::vector<vole_block> q(SECURITY_PARAM * VOLE_COL_BLOCKS);
    std::vector<uint8_t> commitment((BITS_PER_WITNESS - 1) * VOLE_ROWS / 8);
    std::vector<uint8_t> opening(VECTOR_OPEN_SIZE);
    std::array<uint8_t, 2 * SECURITY_PARAM / 8> check_sender;
    std::array<uint8_t, 2 * SECURITY_PARAM / 8> check_receiver;

    vole_commit(seed, forest.data(), hashed_leaves_sender.data(), u.data(), v.data(), commitment.data(), check_sender.data());

    const size_t delta = 42 % (1 << VOLE_MIN_K);

    std::vector<uint8_t> delta_bytes(SECURITY_PARAM, 0);
    for (size_t i = 0, dst = 0; i < BITS_PER_WITNESS; ++i)
    {
        size_t k = i < VOLES_MAX_K ? VOLE_MAX_K : VOLE_MIN_K;
        expand_bits_to_bytes(&delta_bytes[dst], k, delta);
        dst += k;
    }


    vector_open(forest.data(), hashed_leaves_sender.data(), delta_bytes.data(), opening.data());
    vole_reconstruct(q.data(), delta_bytes.data(), commitment.data(), opening.data(), check_receiver.data());

    REQUIRE( check_receiver == check_sender );

    const auto* u_bytes = reinterpret_cast<const uint8_t*>(u.data());
    const auto* v_bytes = reinterpret_cast<const uint8_t*>(v.data());
    const auto* q_bytes = reinterpret_cast<const uint8_t*>(q.data());

    for (size_t i = 0; i < SECURITY_PARAM; ++i) {
        if (delta_bytes[i]) {
            for (size_t j = 0; j < VOLE_ROWS / 8; ++j) {
                REQUIRE( (q_bytes[i * VOLE_COL_BLOCKS * sizeof(vole_block) + j] ^ u_bytes[j])
                        == v_bytes[i * VOLE_COL_BLOCKS * sizeof(vole_block) + j] );
            }
        } else {
            for (size_t j = 0; j < VOLE_ROWS / 8; ++j) {
                REQUIRE( q_bytes[i * VOLE_COL_BLOCKS * sizeof(vole_block) + j]
                        == v_bytes[i * VOLE_COL_BLOCKS * sizeof(vole_block) + j] );
            }
        }
    }
}
