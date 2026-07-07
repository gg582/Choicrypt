/*
 * virtual_silicon.h — Twisted-computation Virtual Silicon VM
 *
 * The VM is intentionally experimental.  It provides:
 *   - 16 x 16-byte registers organised into 4 banks
 *   - key-dependent opcode mapping (keyed ISA)
 *   - runtime opcode twisting based on VM state
 *   - self-modifying bytecode via a rewrite buffer
 *
 * Actual entropy / key-stretching security still relies on
 * /dev/urandom and HMAC-SHA256/PBKDF2 primitives.
 */

#ifndef VIRTUAL_SILICON_H
#define VIRTUAL_SILICON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VS_REG_SIZE       16
#define VS_BANK_SIZE      4
#define VS_NUM_BANKS      4
#define VS_NUM_REGS       (VS_BANK_SIZE * VS_NUM_BANKS)
#define VS_OPCODE_MAP_SIZE 256
#define VS_REWRITE_SIZE   256

typedef enum {
    VS_OP_NOP       = 0x00,
    VS_OP_LOAD      = 0x01,
    VS_OP_STORE     = 0x02,
    VS_OP_XOR       = 0x03,
    VS_OP_ROL       = 0x04,
    VS_OP_SUB       = 0x05,
    VS_OP_SBOX      = 0x06,
    VS_OP_MIX       = 0x07,
    VS_OP_ENTROPY   = 0x08,
    VS_OP_HMAC_STEP = 0x09,
    VS_OP_OBF       = 0x0A,
    VS_OP_BANK      = 0x0B,
    VS_OP_PATCH     = 0x0C,
    VS_OP_HALT      = 0xFF
} vs_opcode;

typedef struct {
    uint8_t  regs[VS_NUM_REGS][VS_REG_SIZE];
    uint8_t  pc;
    uint8_t  bank;                         /* active register bank */
    uint8_t  obf_state;                    /* opcode-twisting state */
    uint64_t cycle;
    uint8_t  opcode_map[VS_OPCODE_MAP_SIZE]; /* key-dependent ISA map */
    uint8_t  rewrite_buf[VS_REWRITE_SIZE];   /* self-modifying workspace */
    uint16_t rewrite_len;
} vs_vm;

/* Identity ISA (no key-dependent remapping). */
void vs_vm_init(vs_vm *vm);

/* Key-dependent ISA: opcode numbers are permuted based on the key. */
void vs_vm_init_keyed(vs_vm *vm, const uint8_t key[VS_REG_SIZE]);

/* Reset pc/cycle; keep registers, bank, opcode map and rewrite buffer. */
void vs_vm_reset(vs_vm *vm);

/* Load/store with bank-relative register indexing. */
void vs_load(vs_vm *vm, uint8_t reg, const uint8_t src[VS_REG_SIZE]);
void vs_store(const vs_vm *vm, uint8_t reg, uint8_t dst[VS_REG_SIZE]);

/* Switch active register bank. */
void vs_switch_bank(vs_vm *vm, uint8_t bank);

/* Execute one instruction from bytecode (using the rewrite buffer).
 * Returns 0 on HALT, 1 otherwise. */
int vs_step(vs_vm *vm, const uint8_t *bytecode, size_t len);

/* Run until HALT or max_cycles. */
void vs_run(vs_vm *vm, const uint8_t *bytecode, size_t len, uint64_t max_cycles);

/* CSPRNG, KDF wrapper, and obfuscation helpers. */
void vs_rng_bytes(const uint8_t seed[VS_REG_SIZE], uint8_t *buf, size_t len);
void vs_kdf(const char *pw, const uint8_t salt[16], uint32_t iter,
            uint8_t *out, size_t outlen);
void vs_obfuscate_block(const uint8_t key[VS_REG_SIZE],
                        uint8_t block[VS_REG_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* VIRTUAL_SILICON_H */
