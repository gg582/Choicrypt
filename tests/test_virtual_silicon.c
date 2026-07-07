/*
 * test_virtual_silicon.c — Unit tests for the expanded Virtual Silicon VM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../virtual_silicon.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("[FAIL] %s\n", msg); \
        failures++; \
    } else { \
        printf("[OK]   %s\n", msg); \
    } \
} while (0)

int main(void) {
    printf("=== test_virtual_silicon ===\n");

    /* 1. VM obfuscation is self-inverse. */
    uint8_t key[VS_REG_SIZE] = "VMSelfInverseKey";
    uint8_t block[VS_REG_SIZE] = "VirtualSilicon!!";
    uint8_t orig[VS_REG_SIZE];
    memcpy(orig, block, VS_REG_SIZE);
    vs_obfuscate_block(key, block);
    ASSERT(memcmp(block, orig, VS_REG_SIZE) != 0, "obfuscation changes block");
    vs_obfuscate_block(key, block);
    ASSERT(memcmp(block, orig, VS_REG_SIZE) == 0, "obfuscation is self-inverse");

    /* 2. VM KDF is deterministic for same input and salt-dependent. */
    uint8_t out1[32], out2[32];
    uint8_t salt[16] = {0};
    vs_kdf("password", salt, 1000, out1, sizeof(out1));
    vs_kdf("password", salt, 1000, out2, sizeof(out2));
    ASSERT(memcmp(out1, out2, sizeof(out1)) == 0, "KDF is deterministic");

    uint8_t salt2[16] = {1, 0};
    uint8_t out3[32];
    vs_kdf("password", salt2, 1000, out3, sizeof(out3));
    ASSERT(memcmp(out1, out3, sizeof(out1)) != 0, "KDF depends on salt");

    /* 3. HALT stops the VM. */
    vs_vm vm;
    vs_vm_init(&vm);
    const uint8_t prog[] = { VS_OP_HALT };
    int running = vs_step(&vm, prog, sizeof(prog));
    ASSERT(running == 0, "HALT stops the VM");

    /* 4. Bank switching isolates register spaces. */
    vs_vm_init(&vm);
    uint8_t pat[VS_REG_SIZE];
    memset(pat, 0xCD, VS_REG_SIZE);
    vs_load(&vm, 0, pat);
    vs_switch_bank(&vm, 1);
    uint8_t zero[VS_REG_SIZE] = {0};
    vs_load(&vm, 0, zero);
    vs_switch_bank(&vm, 0);
    uint8_t r0[VS_REG_SIZE];
    vs_store(&vm, 0, r0);
    ASSERT(memcmp(r0, pat, VS_REG_SIZE) == 0,
           "bank switch keeps original bank register intact");

    /* 5. Key-dependent ISA maps differ for different keys. */
    vs_vm vm_a, vm_b;
    vs_vm_init_keyed(&vm_a, (const uint8_t *)"key_a_key_a_key!");
    vs_vm_init_keyed(&vm_b, (const uint8_t *)"key_b_key_b_key!");
    ASSERT(memcmp(vm_a.opcode_map, vm_b.opcode_map, VS_OPCODE_MAP_SIZE) != 0,
           "different keys produce different opcode maps");

    /* 6. Same key produces same opcode map. */
    vs_vm vm_a2;
    vs_vm_init_keyed(&vm_a2, (const uint8_t *)"key_a_key_a_key!");
    ASSERT(memcmp(vm_a.opcode_map, vm_a2.opcode_map, VS_OPCODE_MAP_SIZE) == 0,
           "same key produces identical opcode map");

    /* 7. Self-modifying bytecode changes rewrite buffer. */
    vs_vm_init(&vm);
    uint8_t mask[VS_REG_SIZE];
    memset(mask, 0x5A, VS_REG_SIZE);
    vs_load(&vm, 0, mask);
    const uint8_t patch_prog[] = {
        VS_OP_PATCH, 4, 1,
        VS_OP_HALT,
        0x00
    };
    uint8_t run_buf[sizeof(patch_prog)];
    memcpy(run_buf, patch_prog, sizeof(patch_prog));
    vs_run(&vm, run_buf, sizeof(patch_prog) - 1, 64);
    ASSERT(vm.rewrite_len >= 1 && vm.rewrite_buf[0] == (0x00 ^ 0x5A),
           "PATCH opcode modifies the rewrite buffer");

    /* 8. VM RNG produces non-trivial output. */
    uint8_t seed[VS_REG_SIZE] = {1};
    uint8_t rng[64];
    vs_rng_bytes(seed, rng, sizeof(rng));
    int all_zero = 1, all_same = 1;
    for (size_t i = 0; i < sizeof(rng); ++i) {
        if (rng[i] != 0) all_zero = 0;
        if (i > 0 && rng[i] != rng[i - 1]) all_same = 0;
    }
    ASSERT(!all_zero, "VM RNG output is not all zeros");
    ASSERT(!all_same, "VM RNG output is not constant");

    if (failures == 0) printf("All Virtual Silicon tests passed.\n");
    else printf("%d test(s) failed.\n", failures);
    return failures ? 1 : 0;
}
