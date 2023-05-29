#include <array>

#include "test.hpp"
#include "test_witness.hpp"

extern "C" {

#include "faest_details.h"

}

#include "catch_amalgamated.hpp"


#if defined(OWF_AES_CTR) && SECURITY_PARAM == 128

TEST_CASE( "unpack sk", "[faest]" ) {
    const auto* key = AES_CTR_128_KEY.data();
    const auto* input = AES_CTR_128_INPUT.data();
    const auto* output = AES_CTR_128_OUTPUT.data();
    const auto* witness = AES_CTR_128_EXTENDED_WITNESS.data();
    REQUIRE( AES_CTR_128_EXTENDED_WITNESS.size() == WITNESS_BITS / 8 );

    std::array<uint8_t, OWF_BLOCKS * OWF_BLOCK_SIZE + SECURITY_PARAM / 8> packed_sk;
    memcpy(packed_sk.data(), input, OWF_BLOCKS * OWF_BLOCK_SIZE);
    memcpy(packed_sk.data() + OWF_BLOCKS * OWF_BLOCK_SIZE, key, SECURITY_PARAM / 8);

    secret_key sk;
    faest_unpack_secret_key(&sk, packed_sk.data());

    const auto computed_output = std::vector(reinterpret_cast<uint8_t*>(sk.pk.owf_output),
                                             reinterpret_cast<uint8_t*>(sk.pk.owf_output) + OWF_BLOCKS * OWF_BLOCK_SIZE);
    const auto expected_output = std::vector(output, output + OWF_BLOCKS * OWF_BLOCK_SIZE);
    const auto computed_witness = std::vector(reinterpret_cast<uint8_t*>(sk.witness),
                                              reinterpret_cast<uint8_t*>(sk.witness) + WITNESS_BITS / 8);
    const auto expected_witness = std::vector(witness, witness + WITNESS_BITS / 8);

    CHECK( computed_output == expected_output );
    CHECK( computed_witness == expected_witness );
}

#endif
