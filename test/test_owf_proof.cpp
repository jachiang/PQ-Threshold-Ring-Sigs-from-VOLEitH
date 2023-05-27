#include <array>

#include "test.hpp"
#include "test_witness.hpp"

extern "C" {

#define restrict __restrict__
#include "owf_proof.h"
#include "quicksilver.h"

}

#include "catch_amalgamated.hpp"


std::pair<std::vector<poly_secpar_vec>, std::vector<poly_secpar_vec>>
gen_vole_correlation(size_t n, const uint8_t* witness, poly_secpar_vec delta) {
    const auto key_vec = random_vector<block_secpar>(n);
    auto keys = std::vector<poly_secpar_vec>(n);
    auto tags = std::vector<poly_secpar_vec>(n);
    for (size_t i = 0; i < n; ++i) {
        const auto p = poly_secpar_load_dup(&key_vec[i]);
        keys[i] = p;
        tags[i] = p;
        if ((witness[i / 8] >> (i % 8)) & 1) {
            tags[i] = poly_secpar_add(tags[i], delta);
        }
    }
    return std::make_pair(keys, tags);
}


#if defined(OWF_AES_CTR) && SECURITY_PARAM == 128

static std::pair<quicksilver_state, quicksilver_state> setup_qs() {
    const size_t num_constraints = 1;
    const auto delta = rand<block_secpar>();
    std::array<uint8_t, QUICKSILVER_CHALLENGE_BYTES> challenge;
    std::generate(challenge.begin(), challenge.end(), rand<uint8_t>);

    const auto* witness = AES_CTR_128_EXTENDED_WITNESS.data();

    const auto [keys, tags] = gen_vole_correlation(1600, witness, poly_secpar_load_dup(&delta));

    quicksilver_state qs_state_prover;
    quicksilver_state qs_state_verifier;
    quicksilver_init_prover(&qs_state_prover, witness, tags.data(), num_constraints, challenge.data());
    quicksilver_init_verifier(&qs_state_verifier, keys.data(), num_constraints, delta, challenge.data());

    return std::make_pair(qs_state_prover, qs_state_verifier);
}


TEST_CASE( "aes128", "[owf proof]" ) {
    auto [qs_state_prover, qs_state_verifier] = setup_qs();

    const auto one_p = quicksilver_one_gfsecpar(&qs_state_prover);
    const auto one_v = quicksilver_one_gfsecpar(&qs_state_verifier);

    owf_constraints_prover(&qs_state_prover);
    owf_constraints_verifier(&qs_state_verifier);

    poly_secpar_vec A0_secpar, A1_secpar, A0_64, A1_64, B_secpar, B_64;
    quicksilver_final(&qs_state_prover, false, &A0_secpar, &A1_secpar, &A0_64, &A1_64);
    quicksilver_final(&qs_state_verifier, true, &B_secpar, NULL, &B_64, NULL);

    const auto delta = quicksilver_get_delta(&qs_state_verifier);

    const auto A1_x_Delta_p_A0_secpar = poly_secpar_add(
            poly_2secpar_reduce_secpar(poly_secpar_mul(delta, A1_secpar)),
            A0_secpar);
    const auto A1_x_Delta_p_A0_64 = poly_secpar_add(
            poly_2secpar_reduce_secpar(poly_secpar_mul(delta, A1_64)),
            A0_64);
    REQUIRE_POLY_SECPAR_VEC_EQ( A1_x_Delta_p_A0_secpar, B_secpar );
    REQUIRE_POLY_SECPAR_VEC_EQ( A1_x_Delta_p_A0_64, B_64 );
}

#endif
