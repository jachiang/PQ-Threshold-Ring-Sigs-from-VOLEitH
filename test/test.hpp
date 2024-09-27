#ifndef TEST_TEST_HPP
#define TEST_TEST_HPP

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#define restrict __restrict__
#include "faest.h"
#include "polynomials.h"
#include "quicksilver.h"
#include "faest_details.h"
}

inline std::string poly_vec_to_string(const uint8_t* buf, size_t poly_size) {
    std::stringstream ss;
    ss << std::hex << "(0x";
    for (size_t i = 0; i < poly_size; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (unsigned) buf[poly_size - i - 1];
    }
    for (size_t j = 1; j < POLY_VEC_LEN; ++j) {
        ss << ", 0x";
        for (size_t i = 0; i < poly_size; ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2) << (unsigned) buf[(j + 1) * poly_size - i - 1];
        }
    }
    ss << ")";
    return ss.str();
}

inline std::string poly64_vec_to_string(poly64_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 8> buf;
    poly64_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 8);
}

inline std::string poly128_vec_to_string(poly128_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 16> buf;
    poly128_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 16);
}

inline std::string poly192_vec_to_string(poly192_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 24> buf;
    poly192_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 24);
}

inline std::string poly256_vec_to_string(poly256_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 32> buf;
    poly256_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 32);
}

inline std::string poly320_vec_to_string(poly320_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 40> buf;
    poly320_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 40);
}

inline std::string poly384_vec_to_string(poly384_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 48> buf;
    poly384_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 48);
}

inline std::string poly512_vec_to_string(poly512_vec pv) {
    std::array<uint8_t, POLY_VEC_LEN * 64> buf;
    poly512_store(buf.data(), pv);
    return poly_vec_to_string(buf.data(), 64);
}

#define REQUIRE_POLY64VEC_EQ(a, b) \
    { INFO("Requiring: " << poly64_vec_to_string(a) << " == " << poly64_vec_to_string(b)); REQUIRE(poly64_eq(a, b)); }
#define REQUIRE_POLY64VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly64_vec_to_string(a) << " != " << poly64_vec_to_string(b)); REQUIRE(!poly64_eq(a, b)); }
#define REQUIRE_POLY128VEC_EQ(a, b) \
    { INFO("Requiring: " << poly128_vec_to_string(a) << " == " << poly128_vec_to_string(b)); REQUIRE(poly128_eq(a, b)); }
#define REQUIRE_POLY128VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly128_vec_to_string(a) << " != " << poly128_vec_to_string(b)); REQUIRE(!poly128_eq(a, b)); }
#define REQUIRE_POLY192VEC_EQ(a, b) \
    { INFO("Requiring: " << poly192_vec_to_string(a) << " == " << poly192_vec_to_string(b)); REQUIRE(poly192_eq(a, b)); }
#define REQUIRE_POLY192VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly192_vec_to_string(a) << " != " << poly192_vec_to_string(b)); REQUIRE(!poly192_eq(a, b)); }
#define REQUIRE_POLY256VEC_EQ(a, b) \
    { INFO("Requiring: " << poly256_vec_to_string(a) << " == " << poly256_vec_to_string(b)); REQUIRE(poly256_eq(a, b)); }
#define REQUIRE_POLY256VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly256_vec_to_string(a) << " != " << poly256_vec_to_string(b)); REQUIRE(!poly256_eq(a, b)); }
#define REQUIRE_POLY320VEC_EQ(a, b) \
    { INFO("Requiring: " << poly320_vec_to_string(a) << " == " << poly320_vec_to_string(b)); REQUIRE(poly320_eq(a, b)); }
#define REQUIRE_POLY320VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly320_vec_to_string(a) << " != " << poly320_vec_to_string(b)); REQUIRE(!poly320_eq(a, b)); }
#define REQUIRE_POLY384VEC_EQ(a, b) \
    { INFO("Requiring: " << poly384_vec_to_string(a) << " == " << poly384_vec_to_string(b)); REQUIRE(poly384_eq(a, b)); }
#define REQUIRE_POLY384VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly384_vec_to_string(a) << " != " << poly384_vec_to_string(b)); REQUIRE(!poly384_eq(a, b)); }
#define REQUIRE_POLY512VEC_EQ(a, b) \
    { INFO("Requiring: " << poly512_vec_to_string(a) << " == " << poly512_vec_to_string(b)); REQUIRE(poly512_eq(a, b)); }
#define REQUIRE_POLY512VEC_NEQ(a, b) \
    { INFO("Requiring: " << poly512_vec_to_string(a) << " != " << poly512_vec_to_string(b)); REQUIRE(!poly512_eq(a, b)); }

#if SECURITY_PARAM == 128
#define REQUIRE_POLY_SECPAR_VEC_EQ(a, b) REQUIRE_POLY128VEC_EQ(a, b)
#elif SECURITY_PARAM == 192
#define REQUIRE_POLY_SECPAR_VEC_EQ(a, b) REQUIRE_POLY192VEC_EQ(a, b)
#elif SECURITY_PARAM == 256
#define REQUIRE_POLY_SECPAR_VEC_EQ(a, b) REQUIRE_POLY256VEC_EQ(a, b)
#endif

inline std::ostream& operator<<(std::ostream& o, const std::vector<uint8_t>& array)
{
	o << "{ ";
	for (size_t i = 0; i < array.size(); ++i)
	{
		if (i)
			o << ", ";
		o << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int) array[i];
	}
	return o << " }";
}

template<size_t N>
inline std::ostream& operator<<(std::ostream& o, const std::array<uint8_t, N>& array)
{
	return o << std::vector(array.begin(), array.end());
}

template <typename T>
inline T rand() {
    static std::mt19937_64 rd(42);
    std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
    return dist(rd);
}

template <>
inline block128 rand<block128>() {
	std::array<uint64_t, 2> data;
	for (size_t i = 0; i < data.size(); ++i)
		data[i] = rand<uint64_t>();

	block128 output;
	memcpy(&output, &data[0], sizeof(output));
	return output;
}

template <>
inline block192 rand<block192>() {
	std::array<uint64_t, 3> data;
	for (size_t i = 0; i < data.size(); ++i)
		data[i] = rand();

	block192 output;
	memcpy(&output, &data[0], sizeof(output));
	return output;
}

template <>
inline block256 rand<block256>() {
	std::array<uint64_t, 4> data;
	for (size_t i = 0; i < data.size(); ++i)
		data[i] = rand();

	block256 output;
	memcpy(&output, &data[0], sizeof(output));
	return output;
}

template <typename T>
inline std::vector<T> random_vector(std::size_t size) {
    std::vector<T> v(size);
    std::generate(v.begin(), v.end(), rand<T>);
    return v;
}

std::pair<std::vector<block_secpar>, std::vector<block_secpar>>
inline gen_vole_correlation(size_t n, const uint8_t* witness, block_secpar delta) {
    const auto keys = random_vector<block_secpar>(n);
    auto tags = keys;
    for (size_t i = 0; i < n; ++i) {
        if ((witness[i / 8] >> (i % 8)) & 1) {
            tags[i] = block_secpar_xor(tags[i], delta);
        }
    }
    return std::make_pair(keys, tags);
}

struct quicksilver_test_state
{
    quicksilver_state prover_state;
    quicksilver_state verifier_state;
    std::vector<uint8_t> witness;
    std::vector<block_secpar> tags;
    std::vector<block_secpar> keys;

    quicksilver_test_state(size_t num_constraints, const uint8_t* witness_in, size_t witness_bits, block_secpar delta) :
        witness(witness_in, witness_in + witness_bits / 8)
    {
        auto witness_mask = random_vector<uint8_t>(SECURITY_PARAM / 8);
        witness.insert(witness.end(), witness_mask.begin(), witness_mask.end());

        auto correlation = gen_vole_correlation(witness_bits + SECURITY_PARAM, witness.data(), delta);
        keys = std::move(correlation.first);
        tags = std::move(correlation.second);

        std::array<uint8_t, QUICKSILVER_CHALLENGE_BYTES> challenge;
        std::generate(challenge.begin(), challenge.end(), rand<uint8_t>);
        quicksilver_init_prover(&prover_state, witness.data(), tags.data(),
                                num_constraints, challenge.data());
        quicksilver_init_verifier(&verifier_state, keys.data(),
                                  num_constraints, delta, challenge.data());
    }

    std::array<std::array<uint8_t, QUICKSILVER_CHECK_BYTES>, 2>
    compute_check() const
    {
        std::array<uint8_t, QUICKSILVER_PROOF_BYTES> proof;
        std::array<uint8_t, QUICKSILVER_CHECK_BYTES> check_prover, check_verifier;

        size_t witness_bits = 8 * witness.size() - SECURITY_PARAM;
        quicksilver_prove(&prover_state, witness_bits, proof.data(), check_prover.data());
        quicksilver_verify(&verifier_state, witness_bits, proof.data(), check_verifier.data());

        return {check_prover, check_verifier};
    }
};

struct quicksilver_test_or_state
{
    quicksilver_state prover_state;
    quicksilver_state verifier_state;
    std::vector<uint8_t> witness;
    std::vector<block_secpar> tags;
    std::vector<block_secpar> keys;

    bool tag;

    quicksilver_test_or_state(size_t num_owf_constraints, const uint8_t* witness_in, size_t witness_bits, block_secpar delta, bool tag) :
        witness(witness_in, witness_in + witness_bits / 8), tag(tag)
    {
        auto witness_mask = random_vector<uint8_t>(SECURITY_PARAM / 8);
        witness.insert(witness.end(), witness_mask.begin(), witness_mask.end());

        auto correlation = gen_vole_correlation(witness_bits + SECURITY_PARAM, witness.data(), delta);
        keys = std::move(correlation.first);
        tags = std::move(correlation.second);

        std::array<uint8_t, QUICKSILVER_CHALLENGE_BYTES> challenge;
        std::generate(challenge.begin(), challenge.end(), rand<uint8_t>);
        // JC: setting "tag = true" inits hasher state for TAGGED_RING_PK_OWF_NUM of enc-sched constraints.
        quicksilver_init_or_prover(&prover_state, witness.data(), tags.data(), challenge.data(), tag);
        quicksilver_init_or_verifier(&verifier_state, keys.data(), delta, challenge.data(), tag);
    }

    std::array<std::array<uint8_t, QUICKSILVER_CHECK_BYTES>, 2>
    compute_check() // JC: No longer const function, as it modifies the prover and verifier state.
    {
        std::array<uint8_t, QUICKSILVER_PROOF_BYTES> proof, proof_quad;
        #if (FAEST_RING_HOTVECTOR_DIM > 1)
        std::array<uint8_t, QUICKSILVER_PROOF_BYTES> proof_cubic;
        #endif
        #if (FAEST_RING_HOTVECTOR_DIM > 2)
        std::array<uint8_t, QUICKSILVER_PROOF_BYTES> proof_quartic;
        #endif
        #if (FAEST_RING_HOTVECTOR_DIM > 3)
        std::array<uint8_t, QUICKSILVER_PROOF_BYTES> proof_quintic;
        #endif

        std::array<uint8_t, QUICKSILVER_CHECK_BYTES> check_prover, check_verifier;

        size_t witness_bits = 8 * witness.size() - SECURITY_PARAM;

        #if (FAEST_RING_HOTVECTOR_DIM == 1)
        quicksilver_prove_or(&prover_state, witness_bits, proof_quad.data(),proof.data(), check_prover.data());
        quicksilver_verify_or(&verifier_state, witness_bits, proof_quad.data(), proof.data(), check_verifier.data());
        #elif (FAEST_RING_HOTVECTOR_DIM == 2)
        quicksilver_prove_or(&prover_state, witness_bits, proof_cubic.data(), proof_quad.data(),proof.data(), check_prover.data());
        quicksilver_verify_or(&verifier_state, witness_bits, proof_cubic.data(), proof_quad.data(), proof.data(), check_verifier.data());
        #elif (FAEST_RING_HOTVECTOR_DIM == 4)
        quicksilver_prove_or(&prover_state, witness_bits, proof_quintic.data(),
                             proof_quartic.data(), proof_cubic.data(), proof_quad.data(),
                             proof.data(), check_prover.data());
        quicksilver_verify_or(&verifier_state, witness_bits, proof_quintic.data(),
                              proof_quartic.data(), proof_cubic.data(), proof_quad.data(), proof.data(), check_verifier.data());
        #endif

        // JC: Free prover/verifier state.
        free(prover_state.state_or_secpar_const);
        free(prover_state.state_or_secpar_linear);
        free(prover_state.state_or_secpar_quad);
        free(prover_state.state_or_64_const);
        free(prover_state.state_or_64_linear);
        free(prover_state.state_or_64_quad);
        free(verifier_state.state_or_secpar_const);
        free(verifier_state.state_or_64_const);

        return {check_prover, check_verifier};
    }
};

// done
inline void test_gen_keypair(unsigned char* pk, unsigned char* sk)
{
	do
	{
        std::generate(sk, sk + FAEST_SECRET_KEY_BYTES, rand<uint8_t>);
	} while (!faest_pubkey(pk, sk));
}

inline void test_gen_ring_keys(public_key_ring* pk_ring, secret_key* sk, uint32_t active_branch)
{
    sk->idx = active_branch;
    for (uint32_t i = 0; i < FAEST_RING_SIZE; ++i) {
        std::array<uint8_t, FAEST_SECRET_KEY_BYTES> packed_sk;
        std::array<uint8_t, FAEST_PUBLIC_KEY_BYTES> packed_pk;
        test_gen_keypair(packed_pk.data(), packed_sk.data());
        faest_unpack_public_key(&pk_ring->pubkeys[i], packed_pk.data());
        if (i == sk->idx) {
            faest_unpack_secret_key(sk, packed_sk.data(), true);
        }
    }
}

#if (TAGGED_RING_PK_OWF_NUM == 2)
inline bool test_gen_keypairs_fixed_owf_inputs(secret_key* sk, public_key* pk0, public_key* pk1, unsigned char* owf_input0, unsigned char* owf_input1)
#elif (TAGGED_RING_PK_OWF_NUM == 3)
inline bool test_gen_keypairs_fixed_owf_inputs(secret_key* sk, public_key* pk0, public_key* pk1, public_key* pk2, unsigned char* owf_input0, unsigned char* owf_input1, unsigned char* owf_input2)
#elif (TAGGED_RING_PK_OWF_NUM == 4)
inline bool test_gen_keypairs_fixed_owf_inputs(secret_key* sk, public_key* pk0, public_key* pk1, public_key* pk2, public_key* pk3, unsigned char* owf_input0, unsigned char* owf_input1, unsigned char* owf_input2, unsigned char* owf_input3)
#endif
{
    std::array<uint8_t, SECURITY_PARAM / 8> owf_key;

    std::generate(owf_key.data(), owf_key.data() + SECURITY_PARAM / 8, rand<uint8_t>);

    // printf("Sampled sk: ");
    // for (int i = 0; i < SECURITY_PARAM / 8; i++) {
    //     printf("%02x", owf_key[i]);
    // }
    // printf("\n");

    // This call packs a specific pk into sk.
    #if (TAGGED_RING_PK_OWF_NUM == 2)
    if(!faest_unpack_secret_key_fixed_owf_inputs(sk, owf_key.data(), owf_input0, owf_input1)) { return false; }
    #elif (TAGGED_RING_PK_OWF_NUM == 3)
    if(!faest_unpack_secret_key_fixed_owf_inputs(sk, owf_key.data(), owf_input0, owf_input1, owf_input2)) { return false; }
    #elif (TAGGED_RING_PK_OWF_NUM == 4)
    if(!faest_unpack_secret_key_fixed_owf_inputs(sk, owf_key.data(), owf_input0, owf_input1, owf_input2, owf_input3)) { return false; }
    #endif

	memcpy(&pk0->owf_input, &sk->pk.owf_input, sizeof(pk0->owf_input));
	memcpy(&pk0->owf_output[0], &sk->pk.owf_output[0], sizeof(pk0->owf_output));
	memcpy(&pk1->owf_input, &sk->pk1.owf_input, sizeof(pk1->owf_input));
	memcpy(&pk1->owf_output[0], &sk->pk1.owf_output[0], sizeof(pk1->owf_output));
    #if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
    memcpy(&pk0->fixed_key, &sk->pk.fixed_key, sizeof(pk0->fixed_key));
    memcpy(&pk1->fixed_key, &sk->pk1.fixed_key, sizeof(pk1->fixed_key));
    #endif
    #if (TAGGED_RING_PK_OWF_NUM > 2)
    memcpy(&pk2->owf_input, &sk->pk2.owf_input, sizeof(pk2->owf_input));
	memcpy(&pk2->owf_output[0], &sk->pk2.owf_output[0], sizeof(pk2->owf_output));
    #if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
    memcpy(&pk2->fixed_key, &sk->pk2.fixed_key, sizeof(pk2->fixed_key));
    #endif
    #endif
    #if (TAGGED_RING_PK_OWF_NUM > 3)
    memcpy(&pk3->owf_input, &sk->pk3.owf_input, sizeof(pk3->owf_input));
	memcpy(&pk3->owf_output[0], &sk->pk3.owf_output[0], sizeof(pk3->owf_output));
    #if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
    memcpy(&pk3->fixed_key, &sk->pk3.fixed_key, sizeof(pk3->fixed_key));
    #endif
    #endif

    // uint8_t val[16];
    // memcpy(&val, pk0->owf_input, sizeof(pk0->owf_input));
    // printf("Fixed owf 0 input (loaded): ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02x", val[i]);
    // }
    // printf("\n");
    // memcpy(&val, pk0->owf_output, sizeof(pk0->owf_output));
    // printf("Fixed owf 0 output (loaded): ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02x", val[i]);
    // }
    // printf("\n");
    // memcpy(&val, &sk->sk, sizeof(sk->sk));
    // printf("sk (loaded): ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02x", val[i]);
    // }
    // printf("\n");

    return true;
}

inline bool test_finalize_sk_for_tag(secret_key* sk, public_key* pk_tag, unsigned char* owf_input_tag)
{
    if(!faest_unpack_secret_key_for_tag(sk, owf_input_tag)) { return false; }

	memcpy(&pk_tag->owf_input[0], &sk->tag.owf_input[0], sizeof(pk_tag->owf_input));
	memcpy(&pk_tag->owf_output[0], &sk->tag.owf_output[0], sizeof(pk_tag->owf_output));
    #if defined(OWF_RIJNDAEL_EVEN_MANSOUR)
    memcpy(&pk_tag->fixed_key, &sk->tag.fixed_key, sizeof(pk_tag->fixed_key));
    #endif

    return true;
}

#if (TAGGED_RING_PK_OWF_NUM == 2)
inline bool test_gen_tagged_ring_keys(secret_key* sk, public_key_ring* pk_ring, uint32_t active_idx, unsigned char* owf_input0, unsigned char* owf_input1)
#elif (TAGGED_RING_PK_OWF_NUM == 3)
inline bool test_gen_tagged_ring_keys(secret_key* sk, public_key_ring* pk_ring, uint32_t active_idx, unsigned char* owf_input0, unsigned char* owf_input1, unsigned char* owf_input2)
#elif (TAGGED_RING_PK_OWF_NUM == 4)
inline bool test_gen_tagged_ring_keys(secret_key* sk, public_key_ring* pk_ring, uint32_t active_idx, unsigned char* owf_input0, unsigned char* owf_input1, unsigned char* owf_input2, unsigned char* owf_input3)
#endif
{
    for (uint32_t i = 0; i < FAEST_RING_SIZE; ++i) {
        secret_key sk_tmp;
        secret_key* sk_ptr;
        if (i == active_idx) {
            sk_ptr = sk;
            sk_ptr->idx = active_idx;
        } else {
            sk_ptr = &sk_tmp;
        }
        sk_tmp.idx = active_idx;
        #if (TAGGED_RING_PK_OWF_NUM == 2)
        if(!test_gen_keypairs_fixed_owf_inputs(sk_ptr, &pk_ring->pubkeys[i], &pk_ring->pubkeys1[i], owf_input0, owf_input1))
        { return false; }
        #elif (TAGGED_RING_PK_OWF_NUM == 3)
        if(!test_gen_keypairs_fixed_owf_inputs(sk_ptr, &pk_ring->pubkeys[i], &pk_ring->pubkeys1[i], &pk_ring->pubkeys2[i], owf_input0, owf_input1, owf_input2))
        { return false; }
        #elif (TAGGED_RING_PK_OWF_NUM == 4)
        if(!test_gen_keypairs_fixed_owf_inputs(sk_ptr, &pk_ring->pubkeys[i], &pk_ring->pubkeys1[i], &pk_ring->pubkeys2[i], &pk_ring->pubkeys3[i], owf_input0, owf_input1, owf_input2, owf_input3)) { return false; }
        #endif
    }
    return true;
}
#endif
