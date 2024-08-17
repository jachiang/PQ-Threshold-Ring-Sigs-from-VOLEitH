#include <array>

#include "test.hpp"
#include "test_witness.hpp"

extern "C" {

#include "api.h"
#include "faest.h"
#include "faest_details.h"
#include "owf_proof.h"

}

#include "catch_amalgamated.hpp"


TEST_CASE( "owf proof", "[owf proof]" ) {
    std::array<uint8_t, FAEST_SECRET_KEY_BYTES> packed_sk;
    std::array<uint8_t, FAEST_PUBLIC_KEY_BYTES> packed_pk;
    test_gen_keypair(packed_pk.data(), packed_sk.data());
    public_key pk;
    secret_key sk;
    faest_unpack_secret_key(&sk, packed_sk.data(), false);
    faest_unpack_public_key(&pk, packed_pk.data());

    const auto delta = rand<block_secpar>();
    quicksilver_test_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.witness), WITNESS_BITS, delta);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover(&qs_state_prover, &pk);
    owf_constraints_verifier(&qs_state_verifier, &pk);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}


TEST_CASE( "ring owf proof", "[ring owf proof]" ) {

    // JC: generate pk-ring.
    public_key_ring pk_ring;
    secret_key sk;
    sk.idx = 15;
    for (size_t i = 0; i < FAEST_RING_SIZE; ++i) {
        std::array<uint8_t, FAEST_SECRET_KEY_BYTES> packed_sk;
        std::array<uint8_t, FAEST_PUBLIC_KEY_BYTES> packed_pk;
        test_gen_keypair(packed_pk.data(), packed_sk.data());
        public_key pk;
        faest_unpack_public_key(&pk, packed_pk.data());
        if (i == sk.idx) {
            // JC: Expanded witness is stored in sk.
            faest_unpack_secret_key(&sk, packed_sk.data(), true);
        }
        pk_ring.pubkeys[i] = pk;
    }

    const auto delta = rand<block_secpar>();
    // TODO: expand witness to accomodate active branch index as secret input.
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.ring_witness), WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8, delta);
    // quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.ring_witness), WITNESS_BITS, delta);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover_all_branches(&qs_state_prover, &pk_ring);
    owf_constraints_verifier_all_branches(&qs_state_verifier, &pk_ring);

	auto [check_prover, check_verifier] = qs_test.compute_check(sk.idx);
    REQUIRE(check_prover == check_verifier);
}