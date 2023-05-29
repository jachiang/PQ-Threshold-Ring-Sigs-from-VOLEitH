#include <array>

#include "test.hpp"
#include "test_witness.hpp"

extern "C" {

#include "faest_details.h"
#include "owf_proof.h"

}

#include "catch_amalgamated.hpp"


#if defined(OWF_AES_CTR) && SECURITY_PARAM == 128

TEST_CASE( "aes-ctr", "[owf proof]" ) {
    const auto* input = AES_CTR_128_INPUT.data();
    const auto* output = AES_CTR_128_OUTPUT.data();
    const auto* witness = AES_CTR_128_EXTENDED_WITNESS.data();

    const auto delta = rand<block_secpar>();
    REQUIRE( WITNESS_BITS == 1600 );
    const size_t num_constraints = OWF_KEY_SCHEDULE_CONSTRAINTS;
    quicksilver_test_state qs_test(num_constraints, witness, WITNESS_BITS, delta);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    public_key pk;
    memcpy(pk.owf_input, input, OWF_BLOCKS * OWF_BLOCK_SIZE);
    memcpy(pk.owf_output, output, OWF_BLOCKS * OWF_BLOCK_SIZE);

    owf_constraints_prover(&qs_state_prover, &pk);
    owf_constraints_verifier(&qs_state_verifier, &pk);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

#endif
