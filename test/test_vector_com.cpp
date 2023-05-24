
#include <array>
#include <vector>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "vector_com.h"

}

#include "catch_amalgamated.hpp"



TEST_CASE( "commit/open/verify", "[vector com]" ) {
    std::array<block_secpar, 2 * BITS_PER_WITNESS> roots = {0};
    std::vector<block_secpar> forest(VECTOR_COMMIT_NODES);
    std::vector<block_secpar> leaves(VECTOR_COMMIT_LEAVES);
    std::vector<block_2secpar> hashed_leaves_sender(VECTOR_COMMIT_LEAVES);
    std::vector<block_2secpar> hashed_leaves_receiver(VECTOR_COMMIT_LEAVES);
    std::vector<uint8_t> delta(SECURITY_PARAM, 0);
    std::vector<unsigned char> opening(VECTOR_OPEN_SIZE);

    vector_commit(roots.data(), NULL, NULL, forest.data(), leaves.data(), hashed_leaves_sender.data());
    vector_open(forest.data(), hashed_leaves_sender.data(), delta.data(), opening.data());
    vector_verify(opening.data(), NULL, NULL, delta.data(), leaves.data(), hashed_leaves_receiver.data());

    const auto hashed_leaves_sender_bytes = std::vector(reinterpret_cast<uint8_t*>(hashed_leaves_sender.data()),
                                                        reinterpret_cast<uint8_t*>(hashed_leaves_sender.data() + hashed_leaves_sender.size()));
    const auto hashed_leaves_receiver_bytes = std::vector(reinterpret_cast<uint8_t*>(hashed_leaves_receiver.data()),
                                                          reinterpret_cast<uint8_t*>(hashed_leaves_receiver.data() + hashed_leaves_receiver.size()));
    REQUIRE( hashed_leaves_receiver_bytes == hashed_leaves_sender_bytes );
}
