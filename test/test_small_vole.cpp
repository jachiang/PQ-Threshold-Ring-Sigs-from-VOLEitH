#include <array>
#include <vector>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "small_vole.h"

}

#include "catch_amalgamated.hpp"



TEST_CASE( "small vole", "[small vole]" ) {
    const size_t k = 10;
    std::vector<block_secpar> sender_keys(1 << k, block_secpar_set_zero());
    std::vector<block_secpar> receiver_keys(1 << k, block_secpar_set_zero());
    std::vector<vole_block> u(VOLE_COL_BLOCKS, vole_block_set_all_8(0));
    std::vector<vole_block> c(VOLE_COL_BLOCKS, vole_block_set_all_8(0));
    std::vector<vole_block> v(k * VOLE_COL_BLOCKS, vole_block_set_all_8(0));
    std::vector<vole_block> q(k * VOLE_COL_BLOCKS, vole_block_set_all_8(0));

    const size_t delta = 42;
    REQUIRE( delta < (1 << k) );

    std::vector<uint8_t> delta_bytes(k, 0);
    expand_bits_to_bytes(delta_bytes.data(), k, delta);

    std::generate(u.begin(), u.end(), rand<vole_block>);

    const auto orig_keys = random_vector<block_secpar>(1 << k);
    for (size_t i = 0; i < (1 << k); ++i) {
        sender_keys[i] = orig_keys[vole_permute_key_index(i)];
        receiver_keys[i] = orig_keys[vole_permute_key_index(i) ^ delta];
    }

    vole_sender(k, sender_keys.data(), NULL, u.data(), v.data(), c.data());
    vole_receiver(k, receiver_keys.data(), NULL, c.data(), q.data(), delta_bytes.data());

    const auto u_vec = std::vector(reinterpret_cast<uint8_t*>(u.data()),
                                   reinterpret_cast<uint8_t*>(u.data() + VOLE_COL_BLOCKS));
    for (size_t i = 0; i < k; ++i) {
        const auto v_vec = std::vector(reinterpret_cast<uint8_t*>(&v[i * VOLE_COL_BLOCKS]),
                                       reinterpret_cast<uint8_t*>(&v[(i + 1) * VOLE_COL_BLOCKS]));
        const auto q_vec = std::vector(reinterpret_cast<uint8_t*>(&q[i * VOLE_COL_BLOCKS]),
                                       reinterpret_cast<uint8_t*>(&q[(i + 1) * VOLE_COL_BLOCKS]));
        auto q_xor_u_vec = q_vec;
        for (size_t j = 0; j < q_vec.size(); ++j) {
            q_xor_u_vec[j] ^= u_vec[j];
        }
        if ((delta >> i) & 1) {
            REQUIRE( v_vec == q_xor_u_vec );
        } else {
            REQUIRE( v_vec == q_vec );
        }
    }
}
