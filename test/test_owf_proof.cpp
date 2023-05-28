#include <array>

#include "test.hpp"
#include "test_witness.hpp"

extern "C" {

#include "owf_proof.h"

}

#include "catch_amalgamated.hpp"


#if defined(OWF_AES_CTR) && SECURITY_PARAM == 128

TEST_CASE( "aes128", "[owf proof]" ) {
    const auto delta = rand<block_secpar>();
    const auto* witness = AES_CTR_128_EXTENDED_WITNESS.data();
    const size_t witness_size = 1600;
    const size_t num_constraints = OWF_KEY_SCHEDULE_CONSTRAINTS;
    quicksilver_test_state qs_test(num_constraints, witness, witness_size, delta);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover(&qs_state_prover);
    owf_constraints_verifier(&qs_state_verifier);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

#endif
