#include "owf_proof.h"
#include "quicksilver.h"

#include "config.h"

#define N_WD (SECURITY_PARAM / 32)

const uint8_t round_constants[15] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
};

void key_sched_fwd(quicksilver_state* state, quicksilver_vec_gf2* output) {
    for (size_t bit_i = 0; bit_i < SECURITY_PARAM; ++bit_i) {
        output[bit_i] = quicksilver_get_witness_vec(state, bit_i);
    }
    // current index in the extended witness
    size_t i_wd = SECURITY_PARAM;
    for (size_t word_j = N_WD; word_j < 4 * (AES_ROUNDS + 1); ++word_j) {
        if (word_j % N_WD == 0 || (N_WD > 6 && word_j % N_WD == 4)) {
            for (size_t bit_i = 0; bit_i < 32; ++bit_i) {
                output[32 * word_j + bit_i] = quicksilver_get_witness_vec(state, i_wd + bit_i);
            }
            i_wd += 32;
        } else {
            for (size_t bit_i = 0; bit_i < 32; ++bit_i) {
                output[32 * word_j + bit_i] = quicksilver_add_gf2(state,
                    output[32 * (word_j - N_WD) + bit_i], output[32 * (word_j - 1) + bit_i]);
            }
        }
    }
}

void key_sched_lift_round_key_bits(quicksilver_state* state, const quicksilver_vec_gf2* round_key_bits,
        quicksilver_vec_gfsecpar* output) {
    for (size_t byte_i = 0; byte_i < OWF_BLOCK_SIZE * (OWF_ROUNDS + 1); ++byte_i) {
        output[byte_i] = quicksilver_combine_8_bits(state, &round_key_bits[8 * byte_i]);
    }
}

void key_sched_bkwd(quicksilver_state* state, const quicksilver_vec_gf2* round_key_bits,
        quicksilver_vec_gfsecpar* output) {
    size_t i_wd = 0; // bit index to the round key word we are currently handling
    size_t i_rcon = 0; // round constant index
    bool remove_rcon = true; // flag indicating if we need to remove the round constant from the
                             // next word
    const quicksilver_vec_gf2 qs_one = quicksilver_one_gf2(state);
    for (size_t sbox_j = 0; sbox_j < OWF_KEY_SCHEDULE_CONSTRAINTS; ++sbox_j) {
        // load the witness byte
        quicksilver_vec_gf2 sbox_out[8];
        for (size_t bit_i = 0; bit_i < 8; ++bit_i) {
            sbox_out[bit_i] = quicksilver_get_witness_vec(state, SECURITY_PARAM + sbox_j * 8 + bit_i);
            // remove the byte that was xored in
            sbox_out[bit_i] = quicksilver_add_gf2(state, sbox_out[bit_i],
                    round_key_bits[i_wd + 8 * (sbox_j % 4) + bit_i]);
        }
        // (possibly) remove the round constant
        if (sbox_j % 4 == 0 && remove_rcon) {
            // remove the round constant from the first byte of every word coming through the sboxes
            for (size_t bit_i = 0; bit_i < 8; ++bit_i) {
                if ((round_constants[i_rcon] >> bit_i) & 1) {
                    sbox_out[bit_i] = quicksilver_add_gf2(state, sbox_out[bit_i], qs_one);
                }
            }
            ++i_rcon;
        }

        quicksilver_vec_gf2 inv_out[8];
        for (size_t i = 0; i < 8; ++i)
            inv_out[(i + 1) % 8] = sbox_out[i];
        for (size_t i = 0; i < 8; ++i)
            inv_out[(i + 3) % 8] = quicksilver_add_gf2(state, inv_out[(i + 3) % 8], sbox_out[i]);
        for (size_t i = 0; i < 8; ++i)
            inv_out[(i + 6) % 8] = quicksilver_add_gf2(state, inv_out[(i + 6) % 8], sbox_out[i]);
        inv_out[0] = quicksilver_add_gf2(state, inv_out[0], qs_one);
        inv_out[2] = quicksilver_add_gf2(state, inv_out[2], qs_one);

        // lift into a field element and store in the output buffer
        output[sbox_j] = quicksilver_combine_8_bits(state, inv_out);

        if (sbox_j % 4 == 3) {
            // increase i_wd to point to the next word
            if (SECURITY_PARAM == 192) {
                i_wd += 192;
            } else {
                i_wd += 128;
                if (SECURITY_PARAM == 256) {
                    remove_rcon = !remove_rcon;
                }
            }
        }
    }
}

void key_sched_constraints(quicksilver_state* state) {
    quicksilver_vec_gf2 round_key_bits[8 * OWF_BLOCK_SIZE * (OWF_ROUNDS + 1)];
    quicksilver_vec_gfsecpar round_key_bytes[OWF_BLOCK_SIZE * (OWF_ROUNDS + 1)];
    quicksilver_vec_gfsecpar key_schedule_inv_outs[OWF_KEY_SCHEDULE_CONSTRAINTS];
    key_sched_fwd(state, round_key_bits);
    key_sched_bkwd(state, round_key_bits, key_schedule_inv_outs);
    key_sched_lift_round_key_bits(state, round_key_bits, round_key_bytes);

    // byte index of the current word to read from the round keys
    size_t i_wd = 4 * (N_WD - 1);
    quicksilver_vec_gfsecpar lhss[4];
    quicksilver_vec_gfsecpar rhss[4];
    for (size_t sboxwd_j = 0; sboxwd_j < OWF_KEY_SCHEDULE_CONSTRAINTS / 4; ++sboxwd_j) {
        for (size_t row_k = 0; row_k < 4; ++row_k) {
            lhss[(row_k + 3) % 4] = round_key_bytes[i_wd + row_k];
            rhss[row_k] = key_schedule_inv_outs[4 * sboxwd_j + row_k];
        }
        for (size_t row_k = 0; row_k < 4; ++row_k) {
            quicksilver_add_product_constraints(state, lhss[row_k], rhss[row_k]);
        }
        break;
        // XXX: incr i_wd
    }

}

ALWAYS_INLINE void owf_constraints(quicksilver_state* state)
{
	// TODO
    key_sched_constraints(state);
}

void owf_constraints_prover(quicksilver_state* state)
{
	assert(!state->verifier);
	owf_constraints(state);
}

void owf_constraints_verifier(quicksilver_state* state)
{
	assert(state->verifier);
	owf_constraints(state);
}
