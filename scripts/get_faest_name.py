import sys

name_table = {
    "sec128_cccs_11_0_pprf": "faest_128s",
    "sec128_cccs_16_0_pprf": "faest_128f",
    "sec192_cccs_16_0_pprf": "faest_192s",
    "sec192_cccs_24_0_pprf": "faest_192f",
    "sec256_cccs_22_0_pprf": "faest_256s",
    "sec256_cccs_32_0_pprf": "faest_256f",
    "sec128_eccs_11_0_pprf": "faest_em_128s",
    "sec128_eccs_16_0_pprf": "faest_em_128f",
    "sec192_eccs_16_0_pprf": "faest_em_192s",
    "sec192_eccs_24_0_pprf": "faest_em_192f",
    "sec256_eccs_22_0_pprf": "faest_em_256s",
    "sec256_eccs_32_0_pprf": "faest_em_256f",
}

if __name__ == '__main__':
    name = sys.argv[1]
    if name in name_table:
        print(name_table[name])
    else:
        print(name)
