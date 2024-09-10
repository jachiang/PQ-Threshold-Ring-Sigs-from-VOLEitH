#include <array>

#include "test.hpp"

extern "C" {

#define restrict __restrict__
#include "rain.h"

}

#include "catch_amalgamated.hpp"

const size_t num_keys = 1;

const uint64_t key_128_3[2] = {0xb61eb19e0ee2444d, 0x4cd8ceac27957eb5};
const uint64_t key_128_4[2] = {0x80cecbca81c371e7, 0xcfa39657231c95b7};
const uint64_t key_192_3[3] = {0xc0a485785b52c047, 0x326075218a8f65ff, 0x986b6c0be0a5a8a6};
const uint64_t key_192_4[3] = {0x15b6f6175caf3f8e, 0xbffb10eacab284a0, 0xebd668e6628903d0};
const uint64_t key_256_3[4] = {0x452dc739a033b5fc, 0xc23e077b8b215eda, 0x7b7b3cdf2a5d51b5, 0x3529e1644e8e0a13};
const uint64_t key_256_4[4] = {0xf70ea236bad9da61, 0x1b30591a3e559195, 0xb4f8cb57a24f3857, 0xfab12d982e449e03};

const uint64_t plaintext_128_3[2] = {0x9cd4e2162a46ec55, 0xc3bf252ca498404d};
const uint64_t plaintext_128_4[2] = {0x83616230e8fd9173, 0xaedeea13a6de87c2};
const uint64_t plaintext_192_3[3] = {0x94d3b85ab94c4b29, 0x815d1101f659285a, 0x9366682858b4579b};
const uint64_t plaintext_192_4[3] = {0x300948af60cfb4e6, 0x2bf78dbc0a0cee9c, 0xf5b8f7fd595ee0fa};
const uint64_t plaintext_256_3[4] = {0x96c5eb2777176599, 0x644f96cda5055d01, 0xfb6450a5cf219109, 0xc36d5b4a51e1f4fa};
const uint64_t plaintext_256_4[4] = {0xdcfed28723e69e8d, 0x83385dc6e28b9ee0, 0x8a7b3cf84223e25c, 0x2079cf036637a381};

const uint64_t expected_ciphertext_128_3[2] = {0x2d77b831e6dea75e, 0xc824f3cfaba5cfb1};
const uint64_t expected_ciphertext_128_4[2] = {0xddf8df897b9cadfd, 0x376685590793c69a};
const uint64_t expected_ciphertext_192_3[3] = {0xb0d7333cf0c5863b, 0xb85e532a2323783f, 0x8c03b12fd56d873f};
const uint64_t expected_ciphertext_192_4[3] = {0x9b0f7cccc954f413, 0x8f59a85c114b6fb7, 0xe46387f07184154d};
const uint64_t expected_ciphertext_256_3[4] = {0xdfa4de29f7cb7302, 0x4f347bd0050e8fdf, 0xb24023925bbdafe8, 0x81dae3155b6c2143};
const uint64_t expected_ciphertext_256_4[4] = {0xb15932a22ee085a6, 0x6bd545dd9fae557c, 0xac8cd552060b3faa, 0xc694dafd0527f425};

// TODO - changed it to #if rain_3 -> #if sec param
TEST_CASE("rain encrypt block") {
#if SECURITY_PARAM == 128 and RAIN_ROUNDS == 3
    printf("\nTesting Rain-3-128\n");
    uint64_t ciphertext_128[2] = {0x00, 0x00};
    memcpy(&ciphertext_128, &plaintext_128_3, 16);
    rain_encrypt_block((uint64_t*)&ciphertext_128, (uint64_t*)&key_128_3);
    for ( uint64_t i = 0; i < 2; i++) {
        REQUIRE(ciphertext_128[i] == expected_ciphertext_128_3[i]);
    }
#elif SECURITY_PARAM == 128 and RAIN_ROUNDS == 4
    printf("\nTesting Rain-4-128\n");
    uint64_t ciphertext_128[2] = {0x00, 0x00};
    memcpy(&ciphertext_128, &plaintext_128_4, 16);
    rain_encrypt_block((uint64_t*)&ciphertext_128, (uint64_t*)&key_128_4);
    for ( uint64_t i = 0; i < 2; i++) {
        REQUIRE(ciphertext_128[i] == expected_ciphertext_128_4[i]);
    }
#elif SECURITY_PARAM == 192 and RAIN_ROUNDS == 3
    printf("\nTesting Rain-3-192\n");
    uint64_t ciphertext_192[3] = {0x00, 0x00, 0x00};
    memcpy(ciphertext_192, plaintext_192_3, 24);
    rain_encrypt_block((uint64_t*)&ciphertext_192, (uint64_t*)&key_192_3);
    for ( uint64_t i = 0; i < 3; i++) {
        REQUIRE(ciphertext_192[i] == expected_ciphertext_192_3[i]);
    }
#elif SECURITY_PARAM == 192 and RAIN_ROUNDS == 4
    printf("\nTesting Rain-4-192\n");
    uint64_t ciphertext_192[3] = {0x00, 0x00, 0x00};
    memcpy(ciphertext_192, plaintext_192_4, 24);
    rain_encrypt_block((uint64_t*)&ciphertext_192, (uint64_t*)&key_192_4);
    for ( uint64_t i = 0; i < 3; i++) {
        REQUIRE(ciphertext_192[i] == expected_ciphertext_192_4[i]);
    }
#elif SECURITY_PARAM == 256 and RAIN_ROUNDS == 3
    printf("\nTesting Rain-3-256\n");
    uint64_t ciphertext_256[4] = {0x00, 0x00, 0x00, 0x00};
    memcpy(&ciphertext_256, &plaintext_256_3, 32);
    rain_encrypt_block((uint64_t*)&ciphertext_256, (uint64_t*)&key_256_3);
    for ( uint64_t i = 0; i < 4; i++) {
        REQUIRE(ciphertext_256[i] == expected_ciphertext_256_3[i]);
    }
#elif SECURITY_PARAM == 256 and RAIN_ROUNDS == 4
    printf("\nTesting Rain-4-256\n");
    uint64_t ciphertext_256[4] = {0x00, 0x00, 0x00, 0x00};
    memcpy(&ciphertext_256, &plaintext_256_4, 32);
    rain_encrypt_block((uint64_t*)&ciphertext_256, (uint64_t*)&key_256_4);
    for ( uint64_t i = 0; i < 4; i++) {
        REQUIRE(ciphertext_256[i] == expected_ciphertext_256_4[i]);
    }
#endif
}