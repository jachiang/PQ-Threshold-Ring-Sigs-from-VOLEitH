#include <array>

#include "test.hpp"

#include "catch_amalgamated.hpp"

#if defined(OWF_MQ_2_8)

#else

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

TEST_CASE( "one", "[quicksilver]" ) {
    const auto delta = rand<block_secpar>();
    quicksilver_test_state qs_test(1, NULL, 0, delta);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    const auto one_p = quicksilver_one_gfsecpar(&qs_state_prover);
    const auto one_v = quicksilver_one_gfsecpar(&qs_state_verifier);

    quicksilver_inverse_constraint(&qs_state_prover, one_p, one_p, false);
    quicksilver_inverse_constraint(&qs_state_verifier, one_v, one_v, false);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

TEST_CASE( "constant", "[quicksilver]" ) {
    const auto delta = rand<block_secpar>();
    quicksilver_test_state qs_test(1, NULL, 0, delta);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    const auto c_42 = poly_secpar_load_dup(BYTES_42.data());
    const auto c_42inv = poly_secpar_load_dup(BYTES_42INV.data());
    const auto c_42_p = quicksilver_const_gfsecpar(&qs_state_prover, c_42);
    const auto c_42_v = quicksilver_const_gfsecpar(&qs_state_verifier, c_42);
    const auto c_42inv_p = quicksilver_const_gfsecpar(&qs_state_prover, c_42inv);
    const auto c_42inv_v = quicksilver_const_gfsecpar(&qs_state_verifier, c_42inv);

    quicksilver_inverse_constraint(&qs_state_prover, c_42_p, c_42inv_p, false);
    quicksilver_inverse_constraint(&qs_state_verifier, c_42_v, c_42inv_v, false);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

TEST_CASE( "mul constant", "[quicksilver]" ) {
    const auto delta = rand<block_secpar>();
    quicksilver_test_state qs_test(1, NULL, 0, delta);
    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    const auto c_42 = poly_secpar_load_dup(BYTES_42.data());
    const auto c_42inv = poly_secpar_load_dup(BYTES_42INV.data());
    const auto c_42_p = quicksilver_const_gfsecpar(&qs_state_prover, c_42);
    const auto c_42_v = quicksilver_const_gfsecpar(&qs_state_verifier, c_42);
    const auto c_42_x_42inv_p = quicksilver_mul_const(&qs_state_prover, c_42_p, c_42inv);
    const auto c_42_x_42inv_v = quicksilver_mul_const(&qs_state_verifier, c_42_v, c_42inv);
    const auto one_p = quicksilver_one_gfsecpar(&qs_state_prover);
    const auto one_v = quicksilver_one_gfsecpar(&qs_state_verifier);

    quicksilver_inverse_constraint(&qs_state_prover, c_42_x_42inv_p, one_p, false);
    quicksilver_inverse_constraint(&qs_state_verifier, c_42_x_42inv_v, one_v, false);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

inline void dot_product_constraints(quicksilver_state* state)
{
    const auto p_42 = poly_secpar_load_dup(BYTES_42.data());
    const auto c_1 = quicksilver_one_gfsecpar(state);
    const auto c_42 = quicksilver_const_gfsecpar(state, p_42);
    const auto c_42_x_1 = quicksilver_mul(state, c_42, c_1);
    const auto c_42_x_1_p_42 = quicksilver_add_deg2(state, c_42_x_1, quicksilver_const_deg2(state, p_42));
    quicksilver_constraint(state, c_42_x_1_p_42, false);
}

TEST_CASE( "dot product", "[quicksilver]" ) {
    const auto delta = rand<block_secpar>();
    quicksilver_test_state qs_test(1, NULL, 0, delta);
    dot_product_constraints(&qs_test.prover_state);
    dot_product_constraints(&qs_test.verifier_state);

	auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

#endif