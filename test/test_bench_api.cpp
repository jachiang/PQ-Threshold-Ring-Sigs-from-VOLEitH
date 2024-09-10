#include <array>

extern "C" {

#include "api.h"


#include <sys/time.h>

long long current_timestamp() {
    struct timeval te; 
    gettimeofday(&te, 0); // get current time
    long long milliseconds = te.tv_sec*1000000LL + te.tv_usec; // calculate milliseconds
    return milliseconds;
}


}

#include "catch_amalgamated.hpp"


TEST_CASE( "bench keygen", "[.][bench]" ) {
    std::array<unsigned char, CRYPTO_SECRETKEYBYTES> sk;
    std::array<unsigned char, CRYPTO_PUBLICKEYBYTES> pk;

    BENCHMARK("keygen") {
        return crypto_sign_keypair(pk.data(), sk.data());
    };
}

TEST_CASE( "bench sign", "[.][bench]" ) {
    std::array<unsigned char, CRYPTO_SECRETKEYBYTES> sk;
    std::array<unsigned char, CRYPTO_PUBLICKEYBYTES> pk;
    crypto_sign_keypair(pk.data(), sk.data());
    const std::string message = "This document describes and specifies the FAEST digital signature algorithm.";
    std::vector<unsigned char> signed_message(CRYPTO_BYTES + message.size());
    unsigned long long signed_message_len;

    BENCHMARK("sign") {
        return crypto_sign(signed_message.data(), &signed_message_len,
                           reinterpret_cast<const unsigned char*>(message.data()), message.size(), sk.data());
    };

    REQUIRE( signed_message_len == signed_message.size() );
}

TEST_CASE( "bench sign", "[.][mybench]" ) {
    std::array<unsigned char, CRYPTO_SECRETKEYBYTES> sk;
    std::array<unsigned char, CRYPTO_PUBLICKEYBYTES> pk;
    crypto_sign_keypair(pk.data(), sk.data());
    std::string message = "This document describes and specifies the FAEST digital signature algorithm.";
    std::vector<unsigned char> signed_message(CRYPTO_BYTES + message.size());
    std::vector<unsigned char> opened_message(message.size());
    unsigned long long signed_message_len;
    unsigned long long opened_message_len;


    unsigned char* m_data = reinterpret_cast<unsigned char*>(message.data());

    #define TEST_SAMPLES 100
    
    long long t = current_timestamp();

    size_t signatures = 0;

    while (current_timestamp() - t < 5000000)
    {
        for (size_t i = 0; i < TEST_SAMPLES; i++)
        {
            message[0] = rand();
            message[1] = rand();
            message[2] = rand();
            message[3] = rand();
            crypto_sign(signed_message.data(), &signed_message_len, m_data, message.size(), sk.data());
            signatures ++;
        }
    }
    
    t = current_timestamp() - t;
    printf("signature bytes: %d\n", CRYPTO_BYTES);
    printf("sign time: %f\n", (t+0.0)/1000/signatures);

    t = current_timestamp();
    signatures = 0;

    while (current_timestamp() - t < 5000000)
    {
        for (size_t i = 0; i < TEST_SAMPLES; i++)
        {
            crypto_sign_open(opened_message.data(), &opened_message_len, signed_message.data(), signed_message_len, pk.data());
            signatures ++;
        }
    }
    
    t = current_timestamp() - t;
    printf("verify time: %f\n", (t+0.0)/1000/signatures);

    REQUIRE( signed_message_len == signed_message.size() );
}

TEST_CASE( "bench verify", "[.][bench]" ) {
    std::array<unsigned char, CRYPTO_SECRETKEYBYTES> sk;
    std::array<unsigned char, CRYPTO_PUBLICKEYBYTES> pk;
    crypto_sign_keypair(pk.data(), sk.data());
    const std::string message = "This document describes and specifies the FAEST digital signature algorithm.";
    std::vector<unsigned char> signed_message(CRYPTO_BYTES + message.size());
    unsigned long long signed_message_len;
    crypto_sign(signed_message.data(), &signed_message_len,
                reinterpret_cast<const unsigned char*>(message.data()), message.size(), sk.data());
    std::vector<unsigned char> opened_message(message.size());
    unsigned long long opened_message_len;

    BENCHMARK("verify") {
        return crypto_sign_open(opened_message.data(), &opened_message_len, signed_message.data(), signed_message_len, pk.data());
    };

    REQUIRE( opened_message_len == opened_message.size() );
    REQUIRE( opened_message == std::vector<unsigned char>(reinterpret_cast<const unsigned char*>(message.c_str()),
                                                          reinterpret_cast<const unsigned char*>(message.c_str()) + message.size()) );
}
