/*
 * obfuscated_pipeline.c — Reversible obfuscation pipeline
 *
 * This module demonstrates a control-flow-flattened pipeline with:
 *   - Tent-map key expansion
 *   - Dynamic P-Box permutation (derangement)
 *   - Virtual-machine bytecode layer
 *   - Rolling round-key feedback
 *
 * Unlike the original version, this implementation is fully invertible:
 * obf_pipeline_decrypt() restores the original state given the same seed
 * and the round keys recorded during encryption.
 */

#include "obfuscated_pipeline.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define OP_XOR  0x01
#define OP_ROL  0x02
#define OP_SBOX 0x03
#define OP_END  0xFF

/* Fixed S-Box (AES) and its inverse.  S-Box is a bijection, so the
 * VM bytecode layer remains fully invertible. */
static const uint8_t OBF_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t OBF_INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* ============================================================
 * Part 1: Key expansion (Tent map)
 * ============================================================ */
static void expand_key_tent_map(const uint8_t seed[32],
                                uint8_t internal_map[2048]) {
    uint32_t x = 0;
    for (int i = 0; i < 32; ++i) {
        x ^= ((uint32_t)seed[i] << ((i % 4) * 8));
    }
    if (x == 0) x = 0x12345678U;

    for (int i = 0; i < 2048; ++i) {
        uint32_t half = 0x80000000U;
        if (x < half) x = x * 2;
        else x = (~x) * 2;
        internal_map[i] = (uint8_t)(x >> 24);
        x ^= 0x9E3779B9U;
    }
}

/* ============================================================
 * Part 2: Dynamic P-Box (derangement) and its inverse
 * ============================================================ */
static void generate_dynamic_pbox(uint32_t control_word,
                                  uint8_t pbox[128],
                                  uint8_t inv_pbox[128]) {
    for (int i = 0; i < 128; ++i) pbox[i] = (uint8_t)i;

    uint32_t lfsr = control_word ? control_word : 0xACE1U;
    for (int i = 127; i > 0; --i) {
        lfsr = (lfsr >> 1) ^ (uint32_t)(-(int32_t)(lfsr & 1U) & 0xD0000001U);
        int j = (int)(lfsr % (uint32_t)(i + 1));
        uint8_t tmp = pbox[i];
        pbox[i] = pbox[j];
        pbox[j] = tmp;
    }

    /* Ensure derangement. */
    for (int i = 0; i < 128; ++i) {
        if (pbox[i] == (uint8_t)i) {
            int swap_idx = (i == 127) ? 0 : (i + 1);
            uint8_t tmp = pbox[i];
            pbox[i] = pbox[swap_idx];
            pbox[swap_idx] = tmp;
        }
    }

    for (int i = 0; i < 128; ++i) inv_pbox[pbox[i]] = (uint8_t)i;
}

static void apply_pbox(const uint8_t pbox[128],
                       const uint8_t in[16],
                       uint8_t out[16]) {
    memset(out, 0, 16);
    for (int i = 0; i < 128; ++i) {
        int src_byte = i / 8;
        int src_bit  = i % 8;
        int dst_byte = pbox[i] / 8;
        int dst_bit  = pbox[i] % 8;
        if (in[src_byte] & (1 << src_bit)) {
            out[dst_byte] |= (1 << dst_bit);
        }
    }
}

/* ============================================================
 * Part 3: Virtual interpreter (encrypt and decrypt bytecodes)
 * ============================================================ */
static void virtual_interpreter_encrypt(const uint8_t *bytecode,
                                        uint8_t state[16]) {
    int pc = 0;
    while (bytecode[pc] != OP_END) {
        uint8_t op = bytecode[pc++];
        if (op == OP_XOR) {
            uint8_t arg = bytecode[pc++];
            for (int i = 0; i < 16; ++i) state[i] ^= arg;
        } else if (op == OP_ROL) {
            uint8_t arg = bytecode[pc++];
            for (int i = 0; i < 16; ++i) {
                state[i] = (uint8_t)((state[i] << arg) | (state[i] >> (8 - arg)));
            }
        } else if (op == OP_SBOX) {
            for (int i = 0; i < 16; ++i) state[i] = OBF_SBOX[state[i]];
        }
    }
}

static void virtual_interpreter_decrypt(const uint8_t *bytecode,
                                        uint8_t state[16]) {
    /* We decrypt by executing the inverse operations in reverse order.
     * First record each instruction's start offset, then execute them
     * backwards.  This avoids the variable-length instruction issue. */
    int starts[64];
    int n = 0;
    int pc = 0;
    while (bytecode[pc] != OP_END) {
        starts[n++] = pc;
        uint8_t op = bytecode[pc++];
        if (op == OP_XOR || op == OP_ROL) pc++;
    }

    for (int i = n - 1; i >= 0; --i) {
        pc = starts[i];
        uint8_t op = bytecode[pc];
        if (op == OP_XOR) {
            uint8_t arg = bytecode[pc + 1];
            for (int j = 0; j < 16; ++j) state[j] ^= arg;
        } else if (op == OP_ROL) {
            uint8_t arg = (uint8_t)(8 - (bytecode[pc + 1] & 7));
            for (int j = 0; j < 16; ++j) {
                state[j] = (uint8_t)((state[j] << arg) | (state[j] >> (8 - arg)));
            }
        } else if (op == OP_SBOX) {
            for (int j = 0; j < 16; ++j) state[j] = OBF_INV_SBOX[state[j]];
        }
    }
}

/* ============================================================
 * Part 5: Round-key injection with rolling feedback
 * ============================================================ */
static void round_key_injection(const uint8_t state[16],
                                const uint8_t round_key[16],
                                uint8_t next_round_key[16]) {
    uint8_t checksum = 0;
    for (int i = 0; i < 16; ++i) {
        uint8_t s = state[i] ^ round_key[i];
        checksum ^= s;
        next_round_key[i] = round_key[i] ^ s ^ 0xA5U;
    }
    next_round_key[0] ^= checksum;
}

/* ============================================================
 * Part 6: Control-flow-flattened encrypt/decrypt dispatcher
 * ============================================================ */
static void pipeline_round_encrypt(uint8_t state[16],
                                   const uint8_t internal_map[2048],
                                   int round,
                                   const uint8_t round_key[16],
                                   uint8_t next_round_key[16]) {
    uint8_t pbox[128], inv_pbox[128];
    generate_dynamic_pbox(internal_map[round * 16] ^ round_key[0], pbox, inv_pbox);
    (void)inv_pbox;

    uint8_t after_pbox[16];
    apply_pbox(pbox, state, after_pbox);
    memcpy(state, after_pbox, 16);

    uint8_t dynamic_xor = round_key[round % 16];
    uint8_t dynamic_rol = (uint8_t)((round_key[(round + 1) % 16] % 7) + 1);
    uint8_t bytecode[] = { OP_XOR, dynamic_xor, OP_SBOX, OP_ROL, dynamic_rol, OP_END };
    virtual_interpreter_encrypt(bytecode, state);

    uint8_t injected[16];
    memcpy(injected, state, 16);
    round_key_injection(injected, round_key, next_round_key);
    for (int i = 0; i < 16; ++i) state[i] = injected[i] ^ round_key[i];
}

static void pipeline_round_decrypt(uint8_t state[16],
                                   const uint8_t internal_map[2048],
                                   int round,
                                   const uint8_t round_key[16]) {
    /* Reverse AddRoundKey. */
    for (int i = 0; i < 16; ++i) state[i] ^= round_key[i];

    /* Reverse VM bytecode. */
    uint8_t dynamic_xor = round_key[round % 16];
    uint8_t dynamic_rol = (uint8_t)((round_key[(round + 1) % 16] % 7) + 1);
    uint8_t bytecode[] = { OP_XOR, dynamic_xor, OP_SBOX, OP_ROL, dynamic_rol, OP_END };
    virtual_interpreter_decrypt(bytecode, state);

    /* Reverse P-Box. */
    uint8_t pbox[128], inv_pbox[128];
    generate_dynamic_pbox(internal_map[round * 16] ^ round_key[0], pbox, inv_pbox);
    (void)pbox;

    uint8_t after_inv[16];
    apply_pbox(inv_pbox, state, after_inv);
    memcpy(state, after_inv, 16);
}

/* ============================================================
 * Part 7: Public API
 * ============================================================ */
void obf_init_round_keys(const uint8_t seed[32],
                         int num_rounds,
                         uint8_t round_keys[OBF_MAX_ROUNDS][OBF_STATE_SIZE]) {
    (void)num_rounds;
    uint8_t internal_map[2048];
    expand_key_tent_map(seed, internal_map);
    memcpy(round_keys[0], internal_map, OBF_STATE_SIZE);
}

void obf_pipeline_encrypt(uint8_t state[OBF_STATE_SIZE],
                          const uint8_t seed[32],
                          int num_rounds,
                          uint8_t round_keys[OBF_MAX_ROUNDS][OBF_STATE_SIZE]) {
    if (num_rounds <= 0 || num_rounds > OBF_MAX_ROUNDS) return;

    uint8_t internal_map[2048];
    expand_key_tent_map(seed, internal_map);
    memcpy(round_keys[0], internal_map, OBF_STATE_SIZE);

    for (int round = 0; round < num_rounds; ++round) {
        uint8_t next_key[OBF_STATE_SIZE];
        pipeline_round_encrypt(state, internal_map, round,
                               round_keys[round], next_key);
        if (round + 1 < num_rounds) {
            memcpy(round_keys[round + 1], next_key, OBF_STATE_SIZE);
        }
    }
}

void obf_pipeline_decrypt(uint8_t state[OBF_STATE_SIZE],
                          const uint8_t seed[32],
                          int num_rounds,
                          const uint8_t round_keys[OBF_MAX_ROUNDS][OBF_STATE_SIZE]) {
    if (num_rounds <= 0 || num_rounds > OBF_MAX_ROUNDS) return;
    (void)seed;

    uint8_t internal_map[2048];
    expand_key_tent_map(seed, internal_map);

    for (int round = num_rounds - 1; round >= 0; --round) {
        pipeline_round_decrypt(state, internal_map, round, round_keys[round]);
    }
}
