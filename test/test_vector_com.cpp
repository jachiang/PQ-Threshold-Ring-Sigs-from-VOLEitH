
#include <array>

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
    std::vector<block_2secpar> hashed_leaves(VECTOR_COMMIT_LEAVES);

    // commit
    // XXX: this currently crashes
    vector_commit(roots.data(), NULL, NULL, forest.data(), leaves.data(), hashed_leaves.data());
}
