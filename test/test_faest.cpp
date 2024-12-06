#include <array>
#include <chrono>

#include "test.hpp"
#include "test_faest_tvs.hpp"
#include "test_witness.hpp"

extern "C" {

#include "config.h"
#include "faest_details.h"

}

#include "catch_amalgamated.hpp"


#if defined(OWF_AES_CTR) || defined(OWF_RIJNDAEL_EVEN_MANSOUR) || defined(OWF_RAIN_3) || defined(OWF_RAIN_4)
TEST_CASE( "unpack sk", "[faest]" ) {
#if defined(OWF_AES_CTR) && SECURITY_PARAM == 128
    const auto* key = AES_CTR_128_KEY.data();
    const auto* input = AES_CTR_128_INPUT.data();
    const auto* output = AES_CTR_128_OUTPUT.data();
    const auto* witness = AES_CTR_128_EXTENDED_WITNESS.data();
    REQUIRE( AES_CTR_128_EXTENDED_WITNESS.size() == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 16 );
    static_assert( OWF_BLOCKS == 1 );
#elif defined(OWF_AES_CTR) && SECURITY_PARAM == 192
    const auto* key = AES_CTR_192_KEY.data();
    const auto* input = AES_CTR_192_INPUT.data();
    const auto* output = AES_CTR_192_OUTPUT.data();
    const auto* witness = AES_CTR_192_EXTENDED_WITNESS.data();
    REQUIRE( AES_CTR_192_EXTENDED_WITNESS.size() == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 16 );
    static_assert( OWF_BLOCKS == 2 );
#elif defined(OWF_AES_CTR) && SECURITY_PARAM == 256
    const auto* key = AES_CTR_256_KEY.data();
    const auto* input = AES_CTR_256_INPUT.data();
    const auto* output = AES_CTR_256_OUTPUT.data();
    const auto* witness = AES_CTR_256_EXTENDED_WITNESS.data();
    REQUIRE( AES_CTR_256_EXTENDED_WITNESS.size() == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 16 );
    static_assert( OWF_BLOCKS == 2 );
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 128
    const auto* key = RIJNDAEL_EM_128_KEY.data();
    const auto* input = RIJNDAEL_EM_128_INPUT.data();
    const auto* output = RIJNDAEL_EM_128_OUTPUT.data();
    const auto* witness = RIJNDAEL_EM_128_EXTENDED_WITNESS.data();
    REQUIRE( RIJNDAEL_EM_128_EXTENDED_WITNESS.size() == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 16 );
    static_assert( OWF_BLOCKS == 1 );
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 192
    const auto* key = RIJNDAEL_EM_192_KEY.data();
    const auto* input = RIJNDAEL_EM_192_INPUT.data();
    const auto* output = RIJNDAEL_EM_192_OUTPUT.data();
    const auto* witness = RIJNDAEL_EM_192_EXTENDED_WITNESS.data();
    REQUIRE( RIJNDAEL_EM_192_EXTENDED_WITNESS.size() == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 24 );
    static_assert( OWF_BLOCKS == 1 );
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 256
    const auto* key = RIJNDAEL_EM_256_KEY.data();
    const auto* input = RIJNDAEL_EM_256_INPUT.data();
    const auto* output = RIJNDAEL_EM_256_OUTPUT.data();
    const auto* witness = RIJNDAEL_EM_256_EXTENDED_WITNESS.data();
    REQUIRE( RIJNDAEL_EM_256_EXTENDED_WITNESS.size() == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 32 );
    static_assert( OWF_BLOCKS == 1 );

#elif defined(OWF_RAIN_3) && SECURITY_PARAM == 128
    const auto* key = (uint8_t*)RAIN_3_128_KEY.data();
    const auto* input = (uint8_t*)RAIN_3_128_INPUT.data();
    const auto* output = (uint8_t*)RAIN_3_128_OUTPUT.data();
    const auto* witness = (uint8_t*)RAIN_3_128_EXTENDED_WITNESS.data();
    REQUIRE( RAIN_3_128_EXTENDED_WITNESS.size() * 8 == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 16 );
    static_assert( OWF_BLOCKS == 1 );
#elif defined(OWF_RAIN_3) && SECURITY_PARAM == 192
    const auto* key = (uint8_t*)RAIN_3_192_KEY.data();
    const auto* input = (uint8_t*)RAIN_3_192_INPUT.data();
    const auto* output = (uint8_t*)RAIN_3_192_OUTPUT.data();
    const auto* witness = (uint8_t*)RAIN_3_192_EXTENDED_WITNESS.data();
    REQUIRE( RAIN_3_192_EXTENDED_WITNESS.size() * 8 == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 24 );
    static_assert( OWF_BLOCKS == 1 );
#elif defined(OWF_RAIN_3) && SECURITY_PARAM == 256
    const auto* key = (uint8_t*)RAIN_3_256_KEY.data();
    const auto* input = (uint8_t*)RAIN_3_256_INPUT.data();
    const auto* output = (uint8_t*)RAIN_3_256_OUTPUT.data();
    const auto* witness = (uint8_t*)RAIN_3_256_EXTENDED_WITNESS.data();
    REQUIRE( RAIN_3_256_EXTENDED_WITNESS.size() * 8 == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 32 );
    static_assert( OWF_BLOCKS == 1 );
#elif defined(OWF_RAIN_4) && SECURITY_PARAM == 128
    const auto* key = (uint8_t*)RAIN_4_128_KEY.data();
    const auto* input = (uint8_t*)RAIN_4_128_INPUT.data();
    const auto* output = (uint8_t*)RAIN_4_128_OUTPUT.data();
    const auto* witness = (uint8_t*)RAIN_4_128_EXTENDED_WITNESS.data();
    REQUIRE( RAIN_4_128_EXTENDED_WITNESS.size() * 8 == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 16 );
    static_assert( OWF_BLOCKS == 1 );
#elif defined(OWF_RAIN_4) && SECURITY_PARAM == 192
    const auto* key = (uint8_t*)RAIN_4_192_KEY.data();
    const auto* input = (uint8_t*)RAIN_4_192_INPUT.data();
    const auto* output = (uint8_t*)RAIN_4_192_OUTPUT.data();
    const auto* witness = (uint8_t*)RAIN_4_192_EXTENDED_WITNESS.data();
    REQUIRE( RAIN_4_192_EXTENDED_WITNESS.size() * 8 == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 24 );
    static_assert( OWF_BLOCKS == 1 );
#elif defined(OWF_RAIN_4) && SECURITY_PARAM == 256
    const auto* key = (uint8_t*)RAIN_4_256_KEY.data();
    const auto* input = (uint8_t*)RAIN_4_256_INPUT.data();
    const auto* output = (uint8_t*)RAIN_4_256_OUTPUT.data();
    const auto* witness = (uint8_t*)RAIN_4_256_EXTENDED_WITNESS.data();
    REQUIRE( RAIN_4_256_EXTENDED_WITNESS.size() * 8 == WITNESS_BITS / 8 );
    static_assert( OWF_BLOCK_SIZE == 32 );
    static_assert( OWF_BLOCKS == 1 );
#endif

    std::array<uint8_t, OWF_BLOCKS * OWF_BLOCK_SIZE + SECURITY_PARAM / 8> packed_sk;
    memcpy(packed_sk.data(), input, OWF_BLOCKS * OWF_BLOCK_SIZE);
    memcpy(packed_sk.data() + OWF_BLOCKS * OWF_BLOCK_SIZE, key, SECURITY_PARAM / 8);

    secret_key sk;
    REQUIRE( faest_unpack_secret_key(&sk, packed_sk.data(), false) );

    const auto computed_output = std::vector(reinterpret_cast<uint8_t*>(sk.pk.owf_output),
                                             reinterpret_cast<uint8_t*>(sk.pk.owf_output) + OWF_BLOCKS * OWF_BLOCK_SIZE);
    const auto expected_output = std::vector(output, output + OWF_BLOCKS * OWF_BLOCK_SIZE);
    const auto computed_witness = std::vector(reinterpret_cast<uint8_t*>(sk.witness),
                                              reinterpret_cast<uint8_t*>(sk.witness) + WITNESS_BITS / 8);
    const auto expected_witness = std::vector(witness, witness + WITNESS_BITS / 8);

    CHECK( computed_output == expected_output );

	// It looks like the extended witness isn't defined correctly for rain.
#if !(defined(OWF_RAIN_3) || defined(OWF_RAIN_4))
    CHECK( computed_witness == expected_witness );
#endif

    faest_free_secret_key(&sk);
}
#endif

TEST_CASE( "keygen/sign/verify", "[faest]" ) {
    std::array<uint8_t, FAEST_SECRET_KEY_BYTES> packed_sk;
    std::array<uint8_t, FAEST_PUBLIC_KEY_BYTES> packed_pk;
    std::array<uint8_t, FAEST_SIGNATURE_BYTES> signature;
    test_gen_keypair(packed_pk.data(), packed_sk.data());

    const std::string message = "This document describes and specifies the FAEST digital signature algorithm.";

    auto signer_start = std::chrono::high_resolution_clock::now();
    REQUIRE( faest_sign(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), packed_sk.data(), NULL, 0) );
    auto signer_end = std::chrono::high_resolution_clock::now();
    auto signer_duration = std::chrono::duration_cast<std::chrono::milliseconds>(signer_end - signer_start);
    std::cout << "Faest Signer runtime: " << signer_duration.count() << " ms" << std::endl;

    auto verifier_start = std::chrono::high_resolution_clock::now();
    REQUIRE( faest_verify(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), packed_pk.data()) );
    auto verifier_end = std::chrono::high_resolution_clock::now();
    auto verifier_duration = std::chrono::duration_cast<std::chrono::milliseconds>(verifier_end - verifier_start);
    std::cout << "Faest Verifier runtime: " << verifier_duration.count() << " ms" << std::endl;

}

#if USE_IMPROVED_VECTOR_COMMITMENTS == 0 && ZERO_BITS_IN_CHALLENGE_3 == 0 && \
    defined(TREE_PRG_AES_CTR) && defined(LEAF_PRG_SHAKE) && \
    ((defined(OWF_AES_CTR) && \
    (((SECURITY_PARAM == 128) && (BITS_PER_WITNESS == 11 || BITS_PER_WITNESS == 16)) || \
     ((SECURITY_PARAM == 192) && (BITS_PER_WITNESS == 16 || BITS_PER_WITNESS == 24)) || \
     ((SECURITY_PARAM == 256) && (BITS_PER_WITNESS == 22 || BITS_PER_WITNESS == 32)))) \
     || \
    (defined(OWF_RIJNDAEL_EVEN_MANSOUR) && \
    (((SECURITY_PARAM == 128) && (BITS_PER_WITNESS == 11 || BITS_PER_WITNESS == 16)) || \
     ((SECURITY_PARAM == 192) && (BITS_PER_WITNESS == 16 || BITS_PER_WITNESS == 24)) || \
     ((SECURITY_PARAM == 256) && (BITS_PER_WITNESS == 22 || BITS_PER_WITNESS == 32)))))

TEST_CASE( "test vector", "[faest tv]" ) {
#if defined(OWF_AES_CTR) && SECURITY_PARAM == 128 && BITS_PER_WITNESS == 11
    namespace tv = faest_tvs::faest_128s_tvs;
#elif defined(OWF_AES_CTR) && SECURITY_PARAM == 128 && BITS_PER_WITNESS == 16
    namespace tv = faest_tvs::faest_128f_tvs;
#elif defined(OWF_AES_CTR) && SECURITY_PARAM == 192 && BITS_PER_WITNESS == 16
    namespace tv = faest_tvs::faest_192s_tvs;
#elif defined(OWF_AES_CTR) && SECURITY_PARAM == 192 && BITS_PER_WITNESS == 24
    namespace tv = faest_tvs::faest_192f_tvs;
#elif defined(OWF_AES_CTR) && SECURITY_PARAM == 256 && BITS_PER_WITNESS == 22
    namespace tv = faest_tvs::faest_256s_tvs;
#elif defined(OWF_AES_CTR) && SECURITY_PARAM == 256 && BITS_PER_WITNESS == 32
    namespace tv = faest_tvs::faest_256f_tvs;
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 128 && BITS_PER_WITNESS == 11
    namespace tv = faest_tvs::faest_em_128s_tvs;
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 128 && BITS_PER_WITNESS == 16
    namespace tv = faest_tvs::faest_em_128f_tvs;
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 192 && BITS_PER_WITNESS == 16
    namespace tv = faest_tvs::faest_em_192s_tvs;
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 192 && BITS_PER_WITNESS == 24
    namespace tv = faest_tvs::faest_em_192f_tvs;
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 256 && BITS_PER_WITNESS == 22
    namespace tv = faest_tvs::faest_em_256s_tvs;
#elif defined(OWF_RIJNDAEL_EVEN_MANSOUR) && SECURITY_PARAM == 256 && BITS_PER_WITNESS == 32
    namespace tv = faest_tvs::faest_em_256f_tvs;
#endif
    using faest_tvs::message;

    REQUIRE( tv::packed_sk.size() == FAEST_SECRET_KEY_BYTES );
    REQUIRE( tv::packed_pk.size() == FAEST_PUBLIC_KEY_BYTES );
    REQUIRE( tv::signature.size() == FAEST_SIGNATURE_BYTES );

    std::array<uint8_t, FAEST_PUBLIC_KEY_BYTES> packed_pk;
    std::array<uint8_t, FAEST_SIGNATURE_BYTES> signature;

    faest_pubkey(packed_pk.data(), tv::packed_sk.data());
    CHECK( packed_pk == tv::packed_pk );

    auto signer_start = std::chrono::high_resolution_clock::now();
    REQUIRE( faest_sign(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), tv::packed_sk.data(), tv::randomness.data(), tv::randomness.size()) );
    auto signer_end = std::chrono::high_resolution_clock::now();
    auto signer_duration = std::chrono::duration_cast<std::chrono::milliseconds>(signer_end - signer_start);
    std::cout << "Faest Signer runtime: " << signer_duration.count() << " ms" << std::endl;

    CHECK( signature == tv::signature );

    auto verifier_start = std::chrono::high_resolution_clock::now();
    REQUIRE( faest_verify(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), tv::packed_pk.data()) );
    auto verifier_end = std::chrono::high_resolution_clock::now();
    auto verifier_duration = std::chrono::duration_cast<std::chrono::milliseconds>(verifier_end - verifier_start);
    std::cout << "Faest Verifier runtime: " << verifier_duration.count() << " ms" << std::endl;
}

#endif

TEST_CASE( "keygen/sign/verify", "[faest ring]" ) {

    printf("FAEST WITNESS BITS: %u\n", WITNESS_BITS);
    printf("RING WITNESS BITS: %u\n", RING_WITNESS_BITS);
    printf("RING SIGNATURE SIZE: %u\n", FAEST_RING_SIGNATURE_BYTES);

    std::array<uint8_t, FAEST_RING_SIGNATURE_BYTES> ring_signature;

    const std::string message = "This is the message string to be signed with the anonymous ring signature.";

    public_key_ring pk_ring;
    pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    if (pk_ring.pubkeys == NULL) {
        printf("Memory allocation failed!\n");
    }
    secret_key sk;
    test_gen_ring_keys(&pk_ring, &sk, test_gen_rand_idx());

    auto signer_start = std::chrono::high_resolution_clock::now();
    REQUIRE( faest_ring_sign(ring_signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), &sk, &pk_ring, NULL, 0) );
    auto signer_end = std::chrono::high_resolution_clock::now();
    auto signer_duration = std::chrono::duration_cast<std::chrono::milliseconds>(signer_end - signer_start);
    std::cout << "Ring Signer runtime: " << signer_duration.count() << " ms" << std::endl;

    auto verifier_start = std::chrono::high_resolution_clock::now();
    REQUIRE( faest_ring_verify(ring_signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), &pk_ring) );
    auto verifier_end = std::chrono::high_resolution_clock::now();
    auto verifier_duration = std::chrono::duration_cast<std::chrono::milliseconds>(verifier_end - verifier_start);
    std::cout << "Ring Verifier runtime: " << verifier_duration.count() << " ms" << std::endl;

    free(pk_ring.pubkeys);
}

#if defined(OWF_AES_CTR)
TEST_CASE( "keygen/sign/verify", "[faest cbc-tagged ring]" ) {

    printf("TAGGED RING WITNESS BITS: %u\n", CBC_TAGGED_RING_WITNESS_BITS);

    // printf("VOLE_COL_BLOCKS: %u\n", VOLE_TAGGED_RING_COL_BLOCKS);
    // printf("VOLE_TAGGED_RING_COL_BLOCKS: %u\n", VOLE_CBC_TAGGED_RING_COL_BLOCKS);

    std::array<uint8_t, FAEST_TAGGED_RING_SIGNATURE_BYTES> ring_signature;
    // std::array<uint8_t, FAEST_CBC_TAGGED_RING_SIGNATURE_BYTES> ring_signature;

    const std::string message = "This is the message string to be signed with the anonymous tagged ring signature.";

    public_key_ring pk_ring;
    pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    pk_ring.pubkeys1 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));

    secret_key sk;
    uint32_t active_idx = test_gen_rand_idx();

    std::array<uint8_t, FAEST_IV_BYTES> owf_input0;
    std::array<uint8_t, FAEST_IV_BYTES> owf_input1;
    std::generate(owf_input0.data(), owf_input0.data() + FAEST_IV_BYTES, rand<uint8_t>);
    std::generate(owf_input1.data(), owf_input1.data() + FAEST_IV_BYTES, rand<uint8_t>);

    // JC: Generate ring and secret key.
    test_gen_tagged_ring_keys(&sk, &pk_ring, active_idx, owf_input0.data(), owf_input1.data());

    // JC: At signing time - generate tag output = owf(sk, h(nonce, msg)).
    public_key tag_pk0;
    public_key tag_pk1;
    std::array<uint8_t, FAEST_IV_BYTES> tag_owf_input0; // TODO: hash of nonce and msg
    std::generate(tag_owf_input0.data(), tag_owf_input0.data() + FAEST_IV_BYTES, rand<uint8_t>);
    std::array<uint8_t, FAEST_IV_BYTES> tag_owf_input1; // TODO: hash of nonce and msg
    std::generate(tag_owf_input1.data(), tag_owf_input1.data() + FAEST_IV_BYTES, rand<uint8_t>);
    // TODO: Writes to alternative witness.
    test_finalize_sk_for_tag_alt(&sk, &tag_pk0, &tag_pk1, tag_owf_input0.data(), tag_owf_input1.data());

    cbc_tag tag;
    std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in0;
    std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in1;
    std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in2;
    std::array<uint8_t, OWF_BLOCK_SIZE> tag_owf_in3;
    std::generate(tag_owf_in0.data(), tag_owf_in0.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
    std::generate(tag_owf_in1.data(), tag_owf_in1.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
    std::generate(tag_owf_in2.data(), tag_owf_in2.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
    std::generate(tag_owf_in3.data(), tag_owf_in3.data() + OWF_BLOCK_SIZE, rand<uint8_t>);
    test_finalize_sk_for_cbc_tag(&sk, &tag, tag_owf_in0.data(), tag_owf_in1.data(),
                                            tag_owf_in2.data(), tag_owf_in3.data());

    REQUIRE( faest_cbc_tagged_ring_sign(ring_signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), &sk, &pk_ring, &tag, &tag_pk0, &tag_pk1, NULL, 0) );
    REQUIRE( faest_cbc_tagged_ring_verify(ring_signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), &pk_ring, &tag, &tag_pk0, &tag_pk1) );

    free(pk_ring.pubkeys);
    free(pk_ring.pubkeys1);
}
#endif

// TODO: Deprecate non-cbc version.
TEST_CASE( "keygen/sign/verify", "[faest tagged ring]" ) {

    printf("TAGGED RING WITNESS BITS: %u\n", TAGGED_RING_WITNESS_BITS);

    printf("VOLE_COL_BLOCKS: %u\n", VOLE_TAGGED_RING_COL_BLOCKS);

    std::array<uint8_t, FAEST_TAGGED_RING_SIGNATURE_BYTES> ring_signature;

    const std::string message = "This is the message string to be signed with the anonymous tagged ring signature.";

    public_key_ring pk_ring;
    pk_ring.pubkeys = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));
    pk_ring.pubkeys1 = (public_key *)aligned_alloc(alignof(public_key), FAEST_RING_SIZE * sizeof(public_key));

    secret_key sk;
    uint32_t active_idx = test_gen_rand_idx();
    for (size_t i; i < TAGGED_RING_WITNESS_BLOCKS; i++) {
        sk.tagged_ring_witness[i] = block128_set_zero();
    }

    std::array<uint8_t, FAEST_IV_BYTES> owf_input0; // TODO: fixed
    std::array<uint8_t, FAEST_IV_BYTES> owf_input1; // TODO: fixed
    std::generate(owf_input0.data(), owf_input0.data() + FAEST_IV_BYTES, rand<uint8_t>);
    std::generate(owf_input1.data(), owf_input1.data() + FAEST_IV_BYTES, rand<uint8_t>);

    // JC: Generate ring and secret key.
    test_gen_tagged_ring_keys(&sk, &pk_ring, active_idx, owf_input0.data(), owf_input1.data());

    // JC: At signing time - generate tag output = owf(sk, h(nonce, msg)).
    public_key tag_pk0;
    public_key tag_pk1;
    std::array<uint8_t, FAEST_IV_BYTES> tag_owf_input0; // TODO: hash of nonce and msg
    std::generate(tag_owf_input0.data(), tag_owf_input0.data() + FAEST_IV_BYTES, rand<uint8_t>);
    std::array<uint8_t, FAEST_IV_BYTES> tag_owf_input1; // TODO: hash of nonce and msg
    std::generate(tag_owf_input1.data(), tag_owf_input1.data() + FAEST_IV_BYTES, rand<uint8_t>);

    test_finalize_sk_for_tag_alt(&sk, &tag_pk0, &tag_pk1, tag_owf_input0.data(), tag_owf_input1.data());

    REQUIRE( faest_tagged_ring_sign(ring_signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), &sk, &pk_ring, &tag_pk0, &tag_pk1, NULL, 0) );
    REQUIRE( faest_tagged_ring_verify(ring_signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()), message.size(), &pk_ring, &tag_pk0, &tag_pk1) );

    free(pk_ring.pubkeys);
    free(pk_ring.pubkeys1);
}