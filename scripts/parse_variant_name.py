import sys

prgs = {
    'c': 'AES_CTR',
    'e': 'RIJNDAEL_EVEN_MANSOUR',
}

leaf_prgs = {**prgs, 's': 'SHAKE'}

owfs = {
    **prgs,
    'r3': 'RAIN_3',
    'r4': 'RAIN_4',
    'mq1': 'MQ_2_1',
    'mq8': 'MQ_2_8',
}

def parse_cipher_abbreviation(ciphers, table):
    for i in range(len(ciphers) + 1):
        prefix = ciphers[:i]
        if prefix in table:
            return table[prefix], ciphers[i:]

    raise ValueError(ciphers + " does not start with a valid cipher abbreviation.")

def parse_variant_name(name):
    secpar, ciphers, tau, zero_bits, seeds_threshold, arch = name.split('_')

    assert secpar[:3] == "sec"
    secpar = int(secpar[3:])

    owf, ciphers = parse_cipher_abbreviation(ciphers, owfs)
    prg, ciphers = parse_cipher_abbreviation(ciphers, prgs)
    tree_prg, ciphers = parse_cipher_abbreviation(ciphers, prgs)
    leaf_prg, ciphers = parse_cipher_abbreviation(ciphers, leaf_prgs)
    assert ciphers == ""

    tau = int(tau)
    zero_bits = int(zero_bits)

    if seeds_threshold == "pprf":
        seeds_threshold = -1
    else:
        seeds_threshold = int(seeds_threshold)

    return secpar, owf, prg, tree_prg, leaf_prg, tau, zero_bits, seeds_threshold, arch

if __name__ == '__main__':
    name = sys.argv[1]
    secpar, owf, prg, tree_prg, leaf_prg, tau, zero_bits, seeds_threshold, arch = parse_variant_name(name)

    print(f"export SECURITY_PARAM={secpar}")
    print(f"export OWF={owf}")
    print(f"export PRG={prg}")
    print(f"export TREE_PRG={tree_prg}")
    print(f"export LEAF_PRG={leaf_prg}")
    print(f"export TAU={tau}")
    print(f"export ZERO_BITS={zero_bits}")
    print(f"export SEEDS_THRESHOLD={seeds_threshold}")
    print(f"export ARCHNAME={arch}")
