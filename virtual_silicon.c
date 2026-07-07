/*
 * virtual_silicon.c — Twisted-computation Virtual Silicon VM
 *
 * See virtual_silicon.h for the security disclaimer.
 */

#include "virtual_silicon.h"
#include "choi_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* Fixed S-Box used inside the VM for non-linear mixing. */
static const uint8_t VS_SBOX[256] = {
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

static inline uint8_t vs_rol8(uint8_t v, uint8_t n) {
    n &= 7;
    return (uint8_t)((v << n) | (v >> (8 - n)));
}

/* Map a bank-relative register index to the physical register index. */
static inline uint8_t vs_phys_reg(const vs_vm *vm, uint8_t reg) {
    return (uint8_t)(((vm->bank % VS_NUM_BANKS) * VS_BANK_SIZE) + (reg % VS_BANK_SIZE));
}

void vs_vm_init(vs_vm *vm) {
    memset(vm, 0, sizeof(*vm));
    for (int i = 0; i < VS_OPCODE_MAP_SIZE; ++i) vm->opcode_map[i] = (uint8_t)i;
}

/* Fisher-Yates shuffle seeded by the key to produce a key-dependent
 * opcode mapping.  The result is a permutation of 0..255. */
static void vs_build_opcode_map(uint8_t map[VS_OPCODE_MAP_SIZE],
                                const uint8_t key[VS_REG_SIZE]) {
    for (int i = 0; i < VS_OPCODE_MAP_SIZE; ++i) map[i] = (uint8_t)i;
    uint32_t state = 0;
    for (int i = 0; i < VS_REG_SIZE; ++i) {
        state ^= ((uint32_t)key[i] << ((i % 4) * 8));
    }
    if (state == 0) state = 0x9E3779B9U;
    for (int i = VS_OPCODE_MAP_SIZE - 1; i > 0; --i) {
        state = state * 1664525U + 1013904223U;
        uint32_t j = (state ^ key[i % VS_REG_SIZE]) % (uint32_t)(i + 1);
        uint8_t tmp = map[i];
        map[i] = map[j];
        map[j] = tmp;
    }
}

void vs_vm_init_keyed(vs_vm *vm, const uint8_t key[VS_REG_SIZE]) {
    vs_vm_init(vm);
    vs_build_opcode_map(vm->opcode_map, key);
}

void vs_vm_reset(vs_vm *vm) {
    vm->pc = 0;
    vm->cycle = 0;
}

void vs_load(vs_vm *vm, uint8_t reg, const uint8_t src[VS_REG_SIZE]) {
    uint8_t r = vs_phys_reg(vm, reg);
    memcpy(vm->regs[r], src, VS_REG_SIZE);
}

void vs_store(const vs_vm *vm, uint8_t reg, uint8_t dst[VS_REG_SIZE]) {
    uint8_t r = vs_phys_reg(vm, reg);
    memcpy(dst, vm->regs[r], VS_REG_SIZE);
}

void vs_switch_bank(vs_vm *vm, uint8_t bank) {
    vm->bank = (uint8_t)(bank % VS_NUM_BANKS);
}

/* Apply runtime opcode twisting on top of the key-dependent map. */
static inline uint8_t vs_resolve_opcode(const vs_vm *vm, uint8_t raw) {
    uint8_t mapped = vm->opcode_map[raw];
    return (uint8_t)((mapped ^ vm->obf_state) + vm->obf_state);
}

static void vs_update_obf(vs_vm *vm, uint8_t reg) {
    uint8_t r = vs_phys_reg(vm, reg);
    uint8_t mix = 0;
    for (int i = 0; i < VS_REG_SIZE; ++i) mix ^= vm->regs[r][i];
    vm->obf_state = (uint8_t)((vm->obf_state * 31) ^ mix ^ vm->bank);
}

/* Read a byte from the active execution image: original bytecode plus
 * the self-modifying rewrite buffer appended after it. */
static uint8_t vs_fetch(const vs_vm *vm, const uint8_t *bytecode, size_t len,
                        uint16_t offset) {
    if (offset < (uint16_t)len) return bytecode[offset];
    uint16_t roff = (uint16_t)(offset - (uint16_t)len);
    if (roff < vm->rewrite_len) return vm->rewrite_buf[roff];
    return VS_OP_HALT;
}

static inline uint8_t vs_fetch_next(vs_vm *vm, const uint8_t *bytecode, size_t len) {
    uint16_t addr = vm->pc;
    vm->pc++;
    return vs_fetch(vm, bytecode, len, addr);
}

int vs_step(vs_vm *vm, const uint8_t *bytecode, size_t len) {
    uint8_t raw = vs_fetch(vm, bytecode, len, vm->pc);
    if (raw == VS_OP_HALT) {
        /* HALT is never remapped so execution always stops cleanly. */
        return 0;
    }
    vm->pc++;
    uint8_t op = vs_resolve_opcode(vm, raw);

    switch (op) {
        case VS_OP_NOP:
            break;

        case VS_OP_LOAD: {
            if ((size_t)vm->pc + 1 > len) return 0;
            uint8_t reg = vs_fetch_next(vm, bytecode, len);
            if ((size_t)vm->pc + VS_REG_SIZE > len) return 0;
            uint8_t r = vs_phys_reg(vm, reg);
            for (int i = 0; i < VS_REG_SIZE; ++i) {
                vm->regs[r][i] = vs_fetch(vm, bytecode, len, (uint16_t)(vm->pc + i));
            }
            vm->pc = (uint8_t)(vm->pc + VS_REG_SIZE);
            vs_update_obf(vm, reg);
            break;
        }

        case VS_OP_STORE: {
            if ((size_t)vm->pc + 1 > len) return 0;
            uint8_t reg = vs_fetch_next(vm, bytecode, len);
            (void)reg;
            vs_update_obf(vm, 0);
            break;
        }

        case VS_OP_XOR: {
            if ((size_t)vm->pc + 2 > len) return 0;
            uint8_t reg = vs_fetch_next(vm, bytecode, len);
            uint8_t imm = vs_fetch_next(vm, bytecode, len);
            uint8_t r = vs_phys_reg(vm, reg);
            for (int i = 0; i < VS_REG_SIZE; ++i)
                vm->regs[r][i] ^= imm;
            vs_update_obf(vm, reg);
            break;
        }

        case VS_OP_ROL: {
            if ((size_t)vm->pc + 2 > len) return 0;
            uint8_t reg = vs_fetch_next(vm, bytecode, len);
            uint8_t imm = vs_fetch_next(vm, bytecode, len);
            uint8_t r = vs_phys_reg(vm, reg);
            for (int i = 0; i < VS_REG_SIZE; ++i)
                vm->regs[r][i] = vs_rol8(vm->regs[r][i], imm);
            vs_update_obf(vm, reg);
            break;
        }

        case VS_OP_SUB: {
            if ((size_t)vm->pc + 2 > len) return 0;
            uint8_t reg = vs_fetch_next(vm, bytecode, len);
            uint8_t imm = vs_fetch_next(vm, bytecode, len);
            uint8_t r = vs_phys_reg(vm, reg);
            for (int i = 0; i < VS_REG_SIZE; ++i)
                vm->regs[r][i] -= (uint8_t)(imm + i);
            vs_update_obf(vm, reg);
            break;
        }

        case VS_OP_SBOX: {
            if ((size_t)vm->pc + 1 > len) return 0;
            uint8_t reg = vs_fetch_next(vm, bytecode, len);
            uint8_t r = vs_phys_reg(vm, reg);
            for (int i = 0; i < VS_REG_SIZE; ++i)
                vm->regs[r][i] = VS_SBOX[vm->regs[r][i]];
            vs_update_obf(vm, reg);
            break;
        }

        case VS_OP_MIX: {
            if ((size_t)vm->pc + 2 > len) return 0;
            uint8_t rdst_raw = vs_fetch_next(vm, bytecode, len);
            uint8_t rsrc_raw = vs_fetch_next(vm, bytecode, len);
            uint8_t rdst = vs_phys_reg(vm, rdst_raw);
            uint8_t rsrc = vs_phys_reg(vm, rsrc_raw);
            for (int i = 0; i < VS_REG_SIZE; ++i) {
                vm->regs[rdst][i] ^= vm->regs[rsrc][i];
                vm->regs[rdst][i] = vs_rol8(vm->regs[rdst][i], 1);
            }
            vs_update_obf(vm, rdst_raw);
            break;
        }

        case VS_OP_ENTROPY: {
            if ((size_t)vm->pc + 1 > len) return 0;
            uint8_t reg = vs_fetch_next(vm, bytecode, len);
            uint8_t r = vs_phys_reg(vm, reg);
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd >= 0) {
                (void)read(fd, vm->regs[r], VS_REG_SIZE);
                close(fd);
            }
            vs_update_obf(vm, reg);
            break;
        }

        case VS_OP_HMAC_STEP: {
            if ((size_t)vm->pc + 3 > len) return 0;
            uint8_t rkey_raw = vs_fetch_next(vm, bytecode, len);
            uint8_t rmsg_raw = vs_fetch_next(vm, bytecode, len);
            uint8_t rout_raw = vs_fetch_next(vm, bytecode, len);
            uint8_t rkey = vs_phys_reg(vm, rkey_raw);
            uint8_t rmsg = vs_phys_reg(vm, rmsg_raw);
            uint8_t rout = vs_phys_reg(vm, rout_raw);
            uint8_t out[32];
            choi_hmac_sha256(vm->regs[rkey], VS_REG_SIZE,
                             vm->regs[rmsg], VS_REG_SIZE, out);
            memcpy(vm->regs[rout], out, VS_REG_SIZE);
            vs_update_obf(vm, rout_raw);
            break;
        }

        case VS_OP_OBF: {
            if ((size_t)vm->pc + 1 > len) return 0;
            uint8_t reg = vs_fetch_next(vm, bytecode, len);
            vs_update_obf(vm, reg);
            break;
        }

        case VS_OP_BANK: {
            if ((size_t)vm->pc + 1 > len) return 0;
            uint8_t bank = vs_fetch_next(vm, bytecode, len);
            vs_switch_bank(vm, bank);
            vs_update_obf(vm, 0);
            break;
        }

        case VS_OP_PATCH: {
            /* Self-modifying bytecode: XOR N bytes of the execution image
             * with register 0 of the current bank.  Unwritten rewrite slots
             * are treated as zero so the first PATCH can initialise them. */
            if ((size_t)vm->pc + 2 > len) return 0;
            uint8_t start = vs_fetch_next(vm, bytecode, len);
            uint8_t count = vs_fetch_next(vm, bytecode, len);
            uint8_t r0 = vs_phys_reg(vm, 0);
            for (uint16_t i = 0; i < count; ++i) {
                uint16_t addr = (uint16_t)(start + i);
                uint8_t val;
                if (addr < (uint16_t)len) {
                    val = bytecode[addr];
                } else {
                    uint16_t roff = (uint16_t)(addr - (uint16_t)len);
                    val = (roff < vm->rewrite_len) ? vm->rewrite_buf[roff] : 0;
                }
                val ^= vm->regs[r0][i % VS_REG_SIZE];
                /* Writes always go into the rewrite buffer, mapped to the
                 * region immediately after the original bytecode. */
                uint16_t roff = (uint16_t)(addr - (uint16_t)len);
                if (roff < VS_REWRITE_SIZE) {
                    vm->rewrite_buf[roff] = val;
                    if (roff + 1 > vm->rewrite_len) vm->rewrite_len = (uint16_t)(roff + 1);
                }
            }
            vs_update_obf(vm, 0);
            break;
        }

        default:
            /* Unknown opcode: treat as NOP to avoid traps. */
            break;
    }

    vm->cycle++;
    return 1;
}

void vs_run(vs_vm *vm, const uint8_t *bytecode, size_t len, uint64_t max_cycles) {
    while (vm->cycle < max_cycles) {
        if (!vs_step(vm, bytecode, len)) break;
    }
}

/* ------------------------------------------------------------------
 * VM-based CSPRNG
 * ------------------------------------------------------------------ */
void vs_rng_bytes(const uint8_t seed[VS_REG_SIZE], uint8_t *buf, size_t len) {
    vs_vm vm;
    vs_vm_init(&vm);
    vs_load(&vm, 0, seed);
    vs_load(&vm, 1, seed);

    /* Program uses bank switching and self-modification to exercise
     * the twisted computation space. */
    const uint8_t prog[] = {
        VS_OP_XOR,   0, 0xA5,
        VS_OP_ROL,   0, 0x03,
        VS_OP_SBOX,  0,
        VS_OP_BANK,  0x01,
        VS_OP_XOR,   0, 0x5A,
        VS_OP_MIX,   0, 1,
        VS_OP_BANK,  0x02,
        VS_OP_ROL,   1, 0x05,
        VS_OP_MIX,   1, 0,
        VS_OP_BANK,  0x03,
        VS_OP_SBOX,  1,
        VS_OP_XOR,   1, 0x37,
        VS_OP_BANK,  0x00,
        VS_OP_MIX,   0, 1,
        VS_OP_SBOX,  0,
        VS_OP_OBF,   0,
        VS_OP_HALT
    };

    size_t offset = 0;
    while (offset < len) {
        vs_vm_reset(&vm);
        vs_run(&vm, prog, sizeof(prog), 128);
        size_t n = (len - offset < VS_REG_SIZE) ? (len - offset) : VS_REG_SIZE;
        memcpy(buf + offset, vm.regs[vs_phys_reg(&vm, 0)], n);
        offset += n;
        uint8_t feedback[VS_REG_SIZE];
        vs_store(&vm, 0, feedback);
        for (size_t i = 0; i < VS_REG_SIZE; ++i)
            feedback[i] ^= (uint8_t)(offset + i + 0xA5U);
        vs_load(&vm, 0, feedback);
    }
}

/* ------------------------------------------------------------------
 * VM-based KDF wrapper around PBKDF2-HMAC-SHA256
 * ------------------------------------------------------------------ */
void vs_kdf(const char *pw, const uint8_t salt[16], uint32_t iter,
            uint8_t *out, size_t outlen) {
    vs_vm vm;
    vs_vm_init(&vm);  /* identity ISA for internal deterministic program */

    uint8_t seed[32];
    choi_hmac_sha256(salt, 16, (const uint8_t *)pw, strlen(pw), seed);
    vs_load(&vm, 0, seed);

    const uint8_t prog[] = {
        VS_OP_BANK, 0x01,
        VS_OP_XOR,  0, 0x9E,
        VS_OP_BANK, 0x02,
        VS_OP_ROL,  0, 0x05,
        VS_OP_BANK, 0x03,
        VS_OP_SBOX, 0,
        VS_OP_BANK, 0x00,
        VS_OP_OBF,  0,
        VS_OP_HALT
    };
    vs_run(&vm, prog, sizeof(prog), 128);

    choi_pbkdf2_hmac_sha256(pw, strlen(pw), salt, 16, iter, out, outlen);
}

/* ------------------------------------------------------------------
 * VM-based obfuscation (self-inverse)
 * ------------------------------------------------------------------ */
void vs_obfuscate_block(const uint8_t key[VS_REG_SIZE],
                        uint8_t block[VS_REG_SIZE]) {
    vs_vm vm;
    vs_vm_init(&vm);  /* identity ISA for internal deterministic program */
    vs_load(&vm, 0, key);
    vs_load(&vm, 1, block);

    /* Self-inverse program: XOR and ROL-by-4 are each self-inverse, so
     * applying the whole sequence twice restores the original block. */
    const uint8_t prog[] = {
        VS_OP_XOR, 1, 0x37,
        VS_OP_ROL, 1, 0x04,  /* ROL by 4 is self-inverse */
        VS_OP_XOR, 1, 0x73,
        VS_OP_ROL, 1, 0x04,
        VS_OP_HALT
    };
    vs_run(&vm, prog, sizeof(prog), 128);
    vs_store(&vm, 1, block);
}
