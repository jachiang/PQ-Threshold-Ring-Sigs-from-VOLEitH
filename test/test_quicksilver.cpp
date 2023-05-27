#include <array>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "quicksilver.h"

}

#include "catch_amalgamated.hpp"

std::array<uint8_t, SECURITY_PARAM / 8> BYTES_42 = {
    0x42,
};
std::array<uint8_t, SECURITY_PARAM / 8> BYTES_42INV = {
#if SECURITY_PARAM == 128
    0x66, 0xe7, 0x9c, 0x73, 0xce, 0x39, 0xe7, 0x9c, 0x73, 0xce, 0x39, 0xe7, 0x9c, 0x73, 0xce, 0xb9, 
#elif SECURITY_PARAM == 192
    0xc2, 0xb5, 0xd6, 0x5a, 0x6b, 0xad, 0xb5, 0xd6, 0x5a, 0x6b, 0xad, 0xb5, 0xd6, 0x5a, 0x6b, 0xad,
    0xb5, 0xd6, 0x5a, 0x6b, 0xad, 0xb5, 0xd6, 0xda, 
#elif SECURITY_PARAM == 256
    0xa5, 0x59, 0x6b, 0xad, 0xb5, 0xd6, 0x5a, 0x6b, 0xad, 0xb5, 0xd6, 0x5a, 0x6b, 0xad, 0xb5, 0xd6,
    0x5a, 0x6b, 0xad, 0xb5, 0xd6, 0x5a, 0x6b, 0xad, 0xb5, 0xd6, 0x5a, 0x6b, 0xad, 0xb5, 0xd6, 0xda, 
#endif
};

std::pair<quicksilver_state, quicksilver_state> setup_qs(size_t num_constraints) {
    const auto delta = rand<block_secpar>();
    std::array<uint8_t, QUICKSILVER_CHALLENGE_BYTES> challenge;
    std::generate(challenge.begin(), challenge.end(), rand<uint8_t>);

    quicksilver_state qs_state_prover;
    quicksilver_state qs_state_verifier;
    quicksilver_init_prover(&qs_state_prover, NULL, NULL, num_constraints, challenge.data());
    quicksilver_init_verifier(&qs_state_verifier, NULL, num_constraints, delta, challenge.data());

    return std::make_pair(qs_state_prover, qs_state_verifier);
}


TEST_CASE( "one", "[quicksilver]" ) {

    const auto num_constraints = 1;
    auto [qs_state_prover, qs_state_verifier] = setup_qs(num_constraints);

    const auto one_p = quicksilver_one_gfsecpar(&qs_state_prover);
    const auto one_v = quicksilver_one_gfsecpar(&qs_state_verifier);

    quicksilver_add_product_constraints(&qs_state_prover, one_p, one_p);
    quicksilver_add_product_constraints(&qs_state_verifier, one_v, one_v);

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

TEST_CASE( "constant", "[quicksilver]" ) {

    const auto num_constraints = 1;
    auto [qs_state_prover, qs_state_verifier] = setup_qs(num_constraints);

    
    const auto c_42 = poly_secpar_load_dup(BYTES_42.data());
    const auto c_42inv = poly_secpar_load_dup(BYTES_42INV.data());
    const auto c_42_p = quicksilver_const_gfsecpar(&qs_state_prover, c_42);
    const auto c_42_v = quicksilver_const_gfsecpar(&qs_state_verifier, c_42);
    const auto c_42inv_p = quicksilver_const_gfsecpar(&qs_state_prover, c_42inv);
    const auto c_42inv_v = quicksilver_const_gfsecpar(&qs_state_verifier, c_42inv);

    quicksilver_add_product_constraints(&qs_state_prover, c_42_p, c_42inv_p);
    quicksilver_add_product_constraints(&qs_state_verifier, c_42_v, c_42inv_v);

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

TEST_CASE( "mul constant", "[quicksilver]" ) {

    const auto num_constraints = 1;
    auto [qs_state_prover, qs_state_verifier] = setup_qs(num_constraints);

    
    const auto c_42 = poly_secpar_load_dup(BYTES_42.data());
    const auto c_42inv = poly_secpar_load_dup(BYTES_42INV.data());
    const auto c_42_p = quicksilver_const_gfsecpar(&qs_state_prover, c_42);
    const auto c_42_v = quicksilver_const_gfsecpar(&qs_state_verifier, c_42);
    const auto c_42_x_42inv_p = quicksilver_mul_const(&qs_state_prover, c_42_p, c_42inv);
    const auto c_42_x_42inv_v = quicksilver_mul_const(&qs_state_verifier, c_42_v, c_42inv);
    const auto one_p = quicksilver_one_gfsecpar(&qs_state_prover);
    const auto one_v = quicksilver_one_gfsecpar(&qs_state_verifier);

    quicksilver_add_product_constraints(&qs_state_prover, c_42_x_42inv_p, one_p);
    quicksilver_add_product_constraints(&qs_state_verifier, c_42_x_42inv_v, one_v);

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
