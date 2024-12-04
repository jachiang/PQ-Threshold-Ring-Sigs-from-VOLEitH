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
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.ring_witness), RING_WITNESS_BITS, delta, false, false); // tag false, cbc false.
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
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.tagged_ring_witness), TAGGED_RING_WITNESS_BITS, delta, true, false); // tag true, cbc false.
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover_all_branches_and_tag(&qs_state_prover, &pk_ring, &tag_pk0, &tag_pk1);
    owf_constraints_verifier_all_branches_and_tag(&qs_state_verifier, &pk_ring, &tag_pk0, &tag_pk1);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);

    free(pk_ring.pubkeys);
    free(pk_ring.pubkeys1);
}

#if defined(OWF_AES_CTR)
// TODO: Implement cbc tag owf step-wise.
// Step 1: Change to
TEST_CASE( "cbc-tagged ring owf proof 3", "[cbc-tagged ring owf proof 3]" ) {
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
    // test_finalize_sk_for_tag(&sk, &tag_pk0, &tag_pk1, tag_owf_input0.data(), tag_owf_input1.data());
    test_finalize_sk_for_tag3(&sk, &tag_pk0, &tag_pk1, tag_owf_input0.data(), tag_owf_input1.data());

    const auto delta = rand<block_secpar>();
    // JC: Witness layout is KEY-SCHED | PK_ENC_SCHED | PK1_ENC_SCHED2 | TAG_ENC_SCHED | TAG_ENC_SCHED1
    // Sets tag flag to true.
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.tagged_ring_witness), TAGGED_RING_WITNESS_BITS3, delta, true, false); // tag true, cbc false.
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover_all_branches_and_tag3(&qs_state_prover, &pk_ring, &tag_pk0, &tag_pk1);
    owf_constraints_verifier_all_branches_and_tag3(&qs_state_verifier, &pk_ring, &tag_pk0, &tag_pk1);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);

    free(pk_ring.pubkeys);
    free(pk_ring.pubkeys1);
}



// TODO: Implements tag OWF individually (non-CBC mode). Does not pass.
TEST_CASE( "cbc-tagged ring owf proof 2", "[cbc-tagged ring owf proof 2]" ) {
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

    // JC: Generate ring keys.
    test_gen_tagged_ring_keys(&sk, &pk_ring, active_idx, owf_input0.data(), owf_input1.data());

    // JC: At signing time - generate tag output = owf(sk, h(msg)) and expand witness.
    cbc_tag tag_cbc;
    std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in0; // Fix to 16 bytes for AES.
    std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in1;
    std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in2;
    std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in3;
    std::generate(tag_owf_in0.data(), tag_owf_in0.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
    std::generate(tag_owf_in1.data(), tag_owf_in1.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
    std::generate(tag_owf_in2.data(), tag_owf_in2.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
    std::generate(tag_owf_in3.data(), tag_owf_in3.data() + OWF_BLOCK_SIZE, rand<uint8_t>);

    // TODO: add second tag owf input.
    // test_finalize_sk_for_tag(&sk, &tag_pk0, &tag_pk1, tag_owf_input0.data(), tag_owf_input1.data());
    test_finalize_sk_for_cbc_tag2(&sk, &tag_cbc, tag_owf_in0.data(), tag_owf_in1.data(), tag_owf_in2.data(), tag_owf_in3.data());

    const auto delta = rand<block_secpar>();
    // // JC: Witness layout is KEY-SCHED | PK_ENC_SCHED | PK1_ENC_SCHED2 | TAG_ENC_SCHED | TAG_ENC_SCHED1
    // // Sets tag flag to true.
    quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.tagged_ring_cbc_witness), TAGGED_RING_CBC_WITNESS_BITS2, delta, true, true); // tag true, cbc true.
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    owf_constraints_prover_all_branches_and_tag_cbc2(&qs_state_prover, &pk_ring, &tag_cbc);
    owf_constraints_verifier_all_branches_and_tag_cbc2(&qs_state_verifier, &pk_ring, &tag_cbc);

	// auto [check_prover, check_verifier] = qs_test.compute_check();
    // REQUIRE(check_prover == check_verifier);

    free(pk_ring.pubkeys);
    free(pk_ring.pubkeys1);
}


// TEST_CASE("cbc-tagged ring owf proof", "[cbc-tagged ring owf proof]") {
//     // For each ring element, there are 2 OWF over fixed inputs(AES)/keys(EM).
//     public_key_ring pk_ring;
//     pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
//     pk_ring.pubkeys1 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));

//     secret_key sk;
//     uint32_t active_idx = test_gen_rand_idx();

// 	// owf_inputs are fixed, and owf_key is identical for all owfs.
//     std::array<uint8_t, FAEST_IV_BYTES> pk_owf_in0; // Size dependent on AES block num.
//     std::array<uint8_t, FAEST_IV_BYTES> pk_owf_in1;
//     std::generate(pk_owf_in0.data(), pk_owf_in0.data() + FAEST_IV_BYTES, rand<uint8_t>);
//     std::generate(pk_owf_in1.data(), pk_owf_in1.data() + FAEST_IV_BYTES, rand<uint8_t>);

//     // Generate ring keys with fixed input blocks.
//     // Generate in/out blocks in pk ring and in/out/sk for active branch in sk.
//     // TODO: distinct input block for each owf (2-4).
//     test_gen_tagged_ring_keys(&sk, &pk_ring, active_idx, pk_owf_in0.data(), pk_owf_in1.data());

//     // JC: At signing time - generate tag output = owf(sk, h(pk || msg)) and expand witness.
//     // Generates tag input blocks (for cbc mode).
//     cbc_tag tag_cbc;
//     std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in0; // Fix to 16 bytes for AES.
//     std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in1;
//     std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in2;
//     std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in3;
//     std::generate(tag_owf_in0.data(), tag_owf_in0.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
//     std::generate(tag_owf_in1.data(), tag_owf_in1.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
//     std::generate(tag_owf_in2.data(), tag_owf_in2.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
//     std::generate(tag_owf_in3.data(), tag_owf_in3.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
//     // JC: Witness layout is KEY | KEY-SCHED | PK_ENC_SCHED | PK1_ENC_SCHED2 | TAG_CBC_SCHED | TAG_CBC_SCHED1 | ...
//     test_finalize_sk_for_cbc_tag(&sk, &tag_cbc, tag_owf_in0.data(), tag_owf_in1.data(), tag_owf_in2.data(), tag_owf_in3.data());
//     // TODO: test that sk.cbc_tag.owf_inputs/output are set correctly.
//     #if (TAGGED_RING_CBC_OWF_NUM > 3)
//     printf("Tag input3: ");
//     for (size_t i = 0; i < OWF_BLOCK_SIZE; i++) {
//         printf("%02x", tag_owf_in3[i]);
// 	}
//     printf("\n");

//     printf("Tag input3 (set in sk): ");
//     unsigned char values[16];
//     _mm_storeu_si128((__m128i*)values, sk.tag_cbc.owf_inputs[3]);
//     for (int i = 0; i < 16; i++) {
//         printf("%02x", values[i]); // Print each byte in hexadecimal
//     }
//     printf("\n");
//     #endif

//     const auto delta = rand<block_secpar>();
//     // TODO: adapt ring witness.
//     quicksilver_test_or_state qs_test(OWF_NUM_CONSTRAINTS, reinterpret_cast<uint8_t*>(sk.tagged_ring_cbc_witness), TAGGED_RING_CBC_WITNESS_BITS, delta, true, true);
//     auto& qs_state_prover = qs_test.prover_state;
//     auto& qs_state_verifier = qs_test.verifier_state;

//     owf_constraints_prover_all_branches_and_tag_cbc(&qs_state_prover, &pk_ring, &tag_cbc);
//     owf_constraints_verifier_all_branches_and_tag_cbc(&qs_state_verifier, &pk_ring, &tag_cbc);

// 	auto [check_prover, check_verifier] = qs_test.compute_check();
//     // REQUIRE(check_prover == check_verifier);

//     // free(pk_ring.pubkeys);
//     // free(pk_ring.pubkeys1);
// }
#endif


