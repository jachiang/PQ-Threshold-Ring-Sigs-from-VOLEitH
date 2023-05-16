
#include <array>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "vector_com.h"

}

#include "catch_amalgamated.hpp"



TEST_CASE( "commit/open/verify", "[vector com]" ) {
    std::array<block_secpar, 2 * BITS_PER_WITNESS> roots = {0};
    std::array<block_secpar, VECTOR_COMMIT_NODES> forest = {0};
    std::array<block_secpar, VECTOR_COMMIT_LEAVES> leaves = {0};
    std::array<block_2secpar, VECTOR_COMMIT_LEAVES> hashed_leaves = {0};

    // commit
    // XXX: this currently crashes
    vector_commit(roots.data(), NULL, NULL, forest.data(), leaves.data(), hashed_leaves.data());
}
