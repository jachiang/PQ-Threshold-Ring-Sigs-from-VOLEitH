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
    std::array<uint8_t, FAEST_PUBLIC_KEY_BYTES> packed_pk2;
    test_gen_keypair(packed_pk.data(), packed_sk.data());

    secret_key sk;
    REQUIRE(faest_unpack_sk_and_get_pubkey(packed_pk2.data(), packed_sk.data(), &sk));
    REQUIRE(packed_pk2 == packed_pk);

    public_key pk;
    faest_unpack_public_key(&pk, packed_pk.data());

    const auto delta = rand<block_secpar>();
    quicksilver_test_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.witness), WITNESS_BITS, delta);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover(&qs_state_prover, &pk);
    owf_constraints_verifier(&qs_state_verifier, &pk);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);

    faest_free_public_key(&pk);
    faest_free_secret_key(&sk);
}

TEST_CASE( "ring owf proof", "[ring owf proof]" ) {
    // for (size_t test_idx = 0; test_idx < FAEST_RING_SIZE; ++test_idx)
    // {
    public_key_ring pk_ring;
    pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    if (pk_ring.pubkeys == NULL) {
        printf("Memory allocation failed!\n");
    }
    secret_key sk;
    test_gen_ring_keys(&pk_ring, &sk, 10);

    const auto delta = rand<block_secpar>();
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.ring_witness), WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8, delta, false);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover_all_branches(&qs_state_prover, &pk_ring, false);
    owf_constraints_verifier_all_branches(&qs_state_verifier, &pk_ring, false);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);

    free(pk_ring.pubkeys);
    // }
}

TEST_CASE( "tagged ring owf proof", "[tagged ring owf proof]" ) {
    // For each ring element, there are 2-4 OWF over fixed inputs(AES)/keys(EM).
    public_key_ring pk_ring;
    pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    pk_ring.pubkeys1 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    #if (TAGGED_RING_PK_OWF_NUM > 2)
    pk_ring.pubkeys2 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    #endif
    #if (TAGGED_RING_PK_OWF_NUM > 3)
    pk_ring.pubkeys3 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    #endif

    secret_key sk;
    uint32_t active_idx = 10;

	// AES: owf_inputs are fixed, and owf_key is identical for all 2-4 owf.
	// EM: owf_keys are fixed, and owf_inputs are identical for all 2-4 owf.
    std::array<uint8_t, FAEST_IV_BYTES> fixed_owf_input0;
    std::array<uint8_t, FAEST_IV_BYTES> fixed_owf_input1;
    std::generate(fixed_owf_input0.data(), fixed_owf_input0.data() + FAEST_IV_BYTES, rand<uint8_t>);
    std::generate(fixed_owf_input1.data(), fixed_owf_input1.data() + FAEST_IV_BYTES, rand<uint8_t>);
    #if (TAGGED_RING_PK_OWF_NUM > 2)
    std::array<uint8_t, FAEST_IV_BYTES> fixed_owf_input2;
    std::generate(fixed_owf_input2.data(), fixed_owf_input2.data() + FAEST_IV_BYTES, rand<uint8_t>);
    #endif
    #if (TAGGED_RING_PK_OWF_NUM > 3)
    std::array<uint8_t, FAEST_IV_BYTES> fixed_owf_input3;
    std::generate(fixed_owf_input3.data(), fixed_owf_input3.data() + FAEST_IV_BYTES, rand<uint8_t>);
    #endif

    printf("Fixed owf 0 input: ");
    for (size_t i = 0; i < FAEST_IV_BYTES; i++) {
        printf("%02x", fixed_owf_input0[i]);
    }
    printf("\n");

    for (uint32_t i = 0; i < FAEST_RING_SIZE; ++i) {
        secret_key sk_tmp;
        sk_tmp.idx = active_idx;
        // JC: sk.idx must set to active branch.
        #if (TAGGED_RING_PK_OWF_NUM == 2)
        test_gen_keypairs_fixed_owf_inputs(&sk_tmp, &pk_ring.pubkeys[i], &pk_ring.pubkeys1[i], fixed_owf_input0.data(), fixed_owf_input1.data());
        #elif (TAGGED_RING_PK_OWF_NUM == 3)
        test_gen_keypairs_fixed_owf_inputs(&sk_tmp, &pk_ring.pubkeys[i], &pk_ring.pubkeys1[i], &pk_ring.pubkeys2[i], fixed_owf_input0.data(), fixed_owf_input1.data(), fixed_owf_input2.data());
        #elif (TAGGED_RING_PK_OWF_NUM == 4)
        test_gen_keypairs_fixed_owf_inputs(&sk_tmp, &pk_ring.pubkeys[i], &pk_ring.pubkeys1[i], &pk_ring.pubkeys2[i], &pk_ring.pubkeys3[i], fixed_owf_input0.data(), fixed_owf_input1.data(), fixed_owf_input2.data(), fixed_owf_input3.data());
        #endif

        if (i == active_idx) {
            memcpy(&sk, &sk_tmp, sizeof(sk));
        }
    }

    // uint8_t val[16];
    // for (uint32_t j = 0; j < RING_WITNESS_BLOCKS; ++j) {
    //     memcpy(&val, &sk.ring_witness[j], sizeof(sk.ring_witness[j]));
    //     printf("Witness block (tag ring owf): ");
    //     for (int i = 0; i < 16; i++) {
    //         printf("%02x", val[i]);
    //     }
    //     printf("\n");
    // }

    const auto delta = rand<block_secpar>();
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.ring_witness), WITNESS_BITS + FAEST_RING_HOTVECTOR_BYTES * 8, delta, false);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover_all_branches(&qs_state_prover, &pk_ring, false);
    owf_constraints_verifier_all_branches(&qs_state_verifier, &pk_ring, false);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);

    free(pk_ring.pubkeys);
    free(pk_ring.pubkeys1);
    #if (TAGGED_RING_PK_OWF_NUM > 2)
    free(pk_ring.pubkeys2);
    #endif
    #if (TAGGED_RING_PK_OWF_NUM > 3)
    free(pk_ring.pubkeys3);
    #endif
}