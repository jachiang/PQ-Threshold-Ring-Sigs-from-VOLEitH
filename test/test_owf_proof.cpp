#include <array>
#include <random>

#include "test.hpp"
#include "test_witness.hpp"
#include <random>
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
    test_gen_ring_keys(&pk_ring, &sk, test_gen_rand_idx());

    const auto delta = rand<block_secpar>();
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.ring_witness), RING_WITNESS_BITS, delta, false); // Sets tag flag to false.
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
    // For each ring element, there are 2 OWF over fixed inputs(AES)/keys(EM).
    public_key_ring pk_ring;
    pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    pk_ring.pubkeys1 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));

    secret_key sk;
    uint32_t active_idx = test_gen_rand_idx();

	// owf_inputs are fixed, and owf_key is identical for all owfs.
    std::array<uint8_t, FAEST_IV_BYTES> owf_input0;
    std::array<uint8_t, FAEST_IV_BYTES> owf_input1;
    std::generate(owf_input0.data(), owf_input0.data() + FAEST_IV_BYTES, rand<uint8_t>);
    std::generate(owf_input1.data(), owf_input1.data() + FAEST_IV_BYTES, rand<uint8_t>);
    // TODO: owf inputs unused.
    #if (TAGGED_RING_PK_OWF_NUM > 2)
    std::array<uint8_t, FAEST_IV_BYTES> owf_input2;
    std::generate(owf_input2.data(), owf_input2.data() + FAEST_IV_BYTES, rand<uint8_t>);
    #endif
    #if (TAGGED_RING_PK_OWF_NUM > 3)
    std::array<uint8_t, FAEST_IV_BYTES> owf_input3;
    std::generate(owf_input3.data(), owf_input3.data() + FAEST_IV_BYTES, rand<uint8_t>);
    #endif

    // JC: Generate ring keys.
    test_gen_tagged_ring_keys(&sk, &pk_ring, active_idx, owf_input0.data(), owf_input1.data());

    // JC: At signing time - generate tag output = owf(sk, h(msg)) and expand witness.
    public_key tag_pk0;
    public_key tag_pk1;
    std::array<uint8_t, FAEST_IV_BYTES> tag_owf_input0;
    std::generate(tag_owf_input0.data(), tag_owf_input0.data() + FAEST_IV_BYTES, rand<uint8_t>);
    std::array<uint8_t, FAEST_IV_BYTES> tag_owf_input1;
    std::generate(tag_owf_input1.data(), tag_owf_input1.data() + FAEST_IV_BYTES, rand<uint8_t>);

    // TODO: add second tag owf input.
    test_finalize_sk_for_tag(&sk, &tag_pk0, &tag_pk1, tag_owf_input0.data(), tag_owf_input1.data());

    const auto delta = rand<block_secpar>();
    // JC: Witness layout is KEY-SCHED | PK_ENC_SCHED | PK1_ENC_SCHED2 | TAG_ENC_SCHED | TAG_ENC_SCHED1
    // Sets tag flag to true.
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.tagged_ring_witness), TAGGED_RING_WITNESS_BITS, delta, true);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover_all_branches_and_tag(&qs_state_prover, &pk_ring, &tag_pk0, &tag_pk1);
    owf_constraints_verifier_all_branches_and_tag(&qs_state_verifier, &pk_ring, &tag_pk0, &tag_pk1);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);

    free(pk_ring.pubkeys);
    free(pk_ring.pubkeys1);
}