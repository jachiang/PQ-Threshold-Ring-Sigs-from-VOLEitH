from math import ceil, floor, log
import sys

from parse_variant_name import parse_variant_name

def faest_vole_commit(tau, sec, ell, B):
    """
    Commitment to the PPRF instances and correction values
     - ell: length of initial random-VOLE instance
    """
    # send one hash for all tau PPRFs
    hash_len = 2*sec
    #correction_values = (ell + tau) * (tau - 1) * logp
    correction_values = ell * (tau - 1)

    #if commit_to_corrections: # NB only possible with 2-out-of-2 sharing
    #    correction_values /= 2
    #    d_elements /= 2

    # VOLE consistency check
    check_u = sec + B
    check_v = hash_len # only send the hash

    # check_v is only hashed, so we don't need to send it. The same is true for the hash of the
    # leaves.
    total = correction_values + check_u
    return total/8

def faest_qs_proof(logp, sec, witness_len):
    commit_to_witness = logp * witness_len
    check_values = 1*sec # There's a second check value, but it's only hashed, so its free.
    return (commit_to_witness + check_values) / 8

def faest_challenge_decom(tau, zero_bits, seeds_threshold, sec):
    """ Response to the last challenge """
    non_zero_bits = sec - zero_bits
    k0 = ceil(non_zero_bits/tau)
    k1 = floor(non_zero_bits/tau)
    tau0 = non_zero_bits % tau
    tau1 = tau - tau0
    assert (k0*tau0 + k1*tau1) == non_zero_bits

    if seeds_threshold == -1:
        open_seeds_bits = non_zero_bits * sec
        counter_bits = 0 if zero_bits == 0 else 32
    else:
        open_seeds_bits = seeds_threshold * sec
        counter_bits = 32

    return (open_seeds_bits + counter_bits + 2*sec*tau)/8

# number of s-box input bytes, excluding the witness
sboxes = {
    128: {'RIJNDAEL_EVEN_MANSOUR': 160 - 16, 'AES_CTR': 200 - 16},
    192: {'RIJNDAEL_EVEN_MANSOUR': 288 - 24, 'AES_CTR': 416 - 2*16},
    256: {'RIJNDAEL_EVEN_MANSOUR': 448 - 32, 'AES_CTR': 500 - 2*16}
}

mq_m = {
    1: {
        128: 152,
        192: 224,
        256: 320,
    },
    8: {
        128: 48,
        192: 72,
        256: 96,
    },
}

def faest_size(witness_length, tau, zero_bits, seeds_threshold, sec):
    # Round up to whole bytes
    witness_length = (witness_length + 7) & -8

    logp = 1
    B = 16 # extra padding bits for VOLE universal hash

    commit_cost = faest_vole_commit(tau, sec, witness_length + 2*sec + B, B) + faest_qs_proof(logp, sec, witness_length)
    open_cost = faest_challenge_decom(tau, zero_bits, seeds_threshold, sec)
    chal3_cost = sec / 8
    iv_cost = 128 / 8
    sig_size = commit_cost + open_cost + chal3_cost + iv_cost

    return round(sig_size)

def aes_witness_length(sec, owf):
    num_sboxes = sboxes[sec][owf]
    #witness_length = 8 * num_sboxes
    witness_length = sec + 8 * num_sboxes
    #witness_length = get_witness_length(sec, EM)

    if owf == "AES_CTR" and sec == 192:
        iv_bits = 256
    else:
        iv_bits = sec
    sk_bytes = (sec + iv_bits) // 8

    if owf == "AES_CTR" and sec == 192:
        pk_bytes = (256 + iv_bits) // 8
    else:
        pk_bytes = sk_bytes

    return sk_bytes, pk_bytes, witness_length

def rain_witness_length(sec, owf):
    assert owf[:5] == "RAIN_"
    num_rounds = int(owf[5:])
    witness_length = num_rounds * sec

    sk_bytes = 2 * sec // 8
    pk_bytes = sk_bytes

    return sk_bytes, pk_bytes, witness_length

def mq_witness_length(sec, owf):
    assert owf[:5] == "MQ_2_"
    field_size = int(owf[5:])
    m = mq_m[field_size][sec]
    witness_length = field_size * m

    sk_bytes = (field_size * m + sec) // 8
    pk_bytes = sk_bytes

    return sk_bytes, pk_bytes, witness_length

if __name__ == '__main__':
    argv = sys.argv
    if argv[1] == "--sed":
        generate_sed_arguments = True
        argv = argv[:1] + argv[2:]
    else:
        generate_sed_arguments = False

    name = argv[1]
    sec, owf, prg, tree_prg, leaf_prg, tau, zero_bits, seeds_threshold, arch = parse_variant_name(name)

    assert(sec in [128, 192, 256])

    if owf in ["AES_CTR", "RIJNDAEL_EVEN_MANSOUR"]:
        sk_bytes, pk_bytes, witness_length = aes_witness_length(sec, owf)
    elif owf in ["RAIN_3", "RAIN_4"]:
        sk_bytes, pk_bytes, witness_length = rain_witness_length(sec, owf)
    elif owf in ["MQ_2_1", "MQ_2_8"]:
        sk_bytes, pk_bytes, witness_length = mq_witness_length(sec, owf)
    else:
        raise ValueError("Invalid one-way function.")

    sig_size = faest_size(witness_length, tau, zero_bits, seeds_threshold, sec)

    if generate_sed_arguments:
        output_arguments = []
        output_arguments.append(f"-e s/%SECRETKEYBYTES%/{sk_bytes}/g")
        output_arguments.append(f"-e s/%PUBLICKEYBYTES%/{pk_bytes}/g")
        output_arguments.append(f"-e s/%SIGBYTES%/{sig_size}/g")

        print(" ".join(output_arguments))

    else:
        print(f"sk:  {sk_bytes} bytes")
        print(f"pk:  {pk_bytes} bytes")
        print(f"sig: {sig_size} bytes")
