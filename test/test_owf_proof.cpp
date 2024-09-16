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
    pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    if (pk_ring.pubkeys == NULL) {
        printf("Memory allocation failed!\n");
    }
    secret_key sk;
    test_gen_ring_keys(&pk_ring, &sk, 12);

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


TEST_CASE( "tagged ring owf proof", "[tagged ring owf proof]" ) {

    public_key_ring pk_ring;
    pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    pk_ring.pubkeys1 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    #if (TAGGED_RING_OWF_NUM > 2)
    pk_ring.pubkeys2 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    #endif
    #if (TAGGED_RING_OWF_NUM > 3)
    pk_ring.pubkeys3 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    #endif

    secret_key sk;
    sk.idx = 12;

	// AES: owf_inputs are fixed, and owf_key is identical for all 2-4 owf.
	// EM: owf_keys are fixed, and owf_inputs are identical for all 2-4 owf.
    std::array<uint8_t, FAEST_IV_BYTES> fixed_owf_input0;
    std::array<uint8_t, FAEST_IV_BYTES> fixed_owf_input1;
    std::generate(fixed_owf_input0.data(), fixed_owf_input0.data() + FAEST_IV_BYTES, rand<uint8_t>);
    std::generate(fixed_owf_input1.data(), fixed_owf_input1.data() + FAEST_IV_BYTES, rand<uint8_t>);
    #if (TAGGED_RING_OWF_NUM > 2)
    std::array<uint8_t, FAEST_IV_BYTES> fixed_owf_input2;
    std::generate(fixed_owf_input2.data(), fixed_owf_input2.data() + FAEST_IV_BYTES, rand<uint8_t>);
    #endif
    #if (TAGGED_RING_OWF_NUM > 3)
    std::array<uint8_t, FAEST_IV_BYTES> fixed_owf_input3;
    std::generate(fixed_owf_input3.data(), fixed_owf_input3.data() + FAEST_IV_BYTES, rand<uint8_t>);
    #endif

    for (uint32_t i = 0; i < FAEST_RING_SIZE; ++i) {
        secret_key sk_tmp;

        #if (TAGGED_RING_OWF_NUM == 2)
        test_gen_keypairs_fixed_owf_inputs(&sk, &pk_ring.pubkeys[i], &pk_ring.pubkeys1[i], fixed_owf_input0.data(), fixed_owf_input1.data());
        #elif (TAGGED_RING_OWF_NUM == 3)
        test_gen_keypairs_fixed_owf_inputs(&sk, &pk_ring.pubkeys[i], &pk_ring.pubkeys1[i], &pk_ring.pubkeys2[i], fixed_owf_input0.data(), fixed_owf_input1.data(), fixed_owf_input2.data());
        #elif (TAGGED_RING_OWF_NUM == 4)
        test_gen_keypairs_fixed_owf_inputs(&sk, &pk_ring.pubkeys[i], &pk_ring.pubkeys1[i], &pk_ring.pubkeys2[i], &pk_ring.pubkeys3[i], fixed_owf_input0.data(), fixed_owf_input1.data(), fixed_owf_input2.data(), fixed_owf_input3.data());
        #endif

        if (i == sk.idx) {
            sk = sk_tmp;
        }
    }
    // TODO.

    free(pk_ring.pubkeys);
    free(pk_ring.pubkeys1);
    #if (TAGGED_RING_OWF_NUM > 2)
    free(pk_ring.pubkeys2);
    #endif
    #if (TAGGED_RING_OWF_NUM > 3)
    free(pk_ring.pubkeys3);
    #endif
}