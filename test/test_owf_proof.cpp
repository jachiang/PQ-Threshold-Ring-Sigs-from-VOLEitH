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
    // for (size_t test_idx = 0; test_idx < FAEST_RING_SIZE; ++test_idx)
    // {
    public_key_ring pk_ring;
    pk_ring.pubkeys = (public_key *)malloc(FAEST_RING_SIZE * sizeof(public_key));

    secret_key sk;
    // sk.idx = test_idx;
    sk.idx = 12;
    for (uint32_t i = 0; i < FAEST_RING_SIZE; ++i) {
        std::array<uint8_t, FAEST_SECRET_KEY_BYTES> packed_sk;
        std::array<uint8_t, FAEST_PUBLIC_KEY_BYTES> packed_pk;
        test_gen_keypair(packed_pk.data(), packed_sk.data());
        faest_unpack_public_key(&pk_ring.pubkeys[i], packed_pk.data());
        if (i == sk.idx) {
            // JC: Expanded witness encodes active branch and is stored in sk.
            faest_unpack_secret_key(&sk, packed_sk.data(), true);
        }
    }
    const auto delta = rand<block_secpar>();
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.ring_witness), WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover_all_branches(&qs_state_prover, &pk_ring);
    owf_constraints_verifier_all_branches(&qs_state_verifier, &pk_ring);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);

    free(pk_ring.pubkeys);
    // }
}