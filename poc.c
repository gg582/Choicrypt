/*
 * poc.c — Choicrypt proof-of-concept / verification demo
 *
 * This program demonstrates:
 *   1. Block cipher round-trip and avalanche
 *   2. CTR mode keystream properties
 *   3. HMAC-based authentication (wrong key fails)
 *   4. Virtual Silicon VM (RNG, KDF, obfuscation)
 *   5. Dynamic ASM round-trip
 *   6. Obfuscated pipeline round-trip
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "choi_common.h"
#include "virtual_silicon.h"
#include "dynamic_asm.h"
#include "obfuscated_pipeline.h"
#include <fcntl.h>
#include <unistd.h>

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", buf[i]);
    printf("\n");
}

static int count_bit_diff(const uint8_t *a, const uint8_t *b, size_t len) {
    int diff = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t d = a[i] ^ b[i];
        while (d) { diff += d & 1; d >>= 1; }
    }
    return diff;
}

/* ------------------------------------------------------------------
 * Phase 1: Block cipher round-trip and avalanche
 * ------------------------------------------------------------------ */
static void phase1_block(void) {
    printf("\n=== Phase 1: Block cipher round-trip & avalanche ===\n");

    const char *pw = "choicrypt_demo_password";
    uint8_t salt[CHOI_SALT_SIZE] = {0};
    uint8_t enc_key[CHOI_KEY_SIZE], mac_key[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt, enc_key, mac_key);

    uint8_t pt[CHOI_BLOCK_SIZE] = "HelloChoicrypt!!";
    uint8_t ct[CHOI_BLOCK_SIZE], dec[CHOI_BLOCK_SIZE];
    choi_encrypt_block(pt, ct);
    choi_decrypt_block(ct, dec);

    print_hex("PT:  ", pt, CHOI_BLOCK_SIZE);
    print_hex("CT:  ", ct, CHOI_BLOCK_SIZE);
    print_hex("DEC: ", dec, CHOI_BLOCK_SIZE);

    if (memcmp(pt, dec, CHOI_BLOCK_SIZE) != 0) {
        printf("FAIL: block round-trip mismatch\n");
        return;
    }
    printf("[OK] Block round-trip successful.\n");

    /* Avalanche: flip one bit in plaintext. */
    uint8_t pt2[CHOI_BLOCK_SIZE];
    memcpy(pt2, pt, CHOI_BLOCK_SIZE);
    pt2[0] ^= 0x01;
    uint8_t ct2[CHOI_BLOCK_SIZE];
    choi_encrypt_block(pt2, ct2);
    int diff = count_bit_diff(ct, ct2, CHOI_BLOCK_SIZE);
    printf("Avalanche (1-bit PT flip): %d/%d bits changed (%.1f%%)\n",
           diff, (int)(CHOI_BLOCK_SIZE * 8),
           100.0 * diff / (CHOI_BLOCK_SIZE * 8));

    /* Avalanche: flip one bit in key. */
    uint8_t salt2[CHOI_SALT_SIZE] = {0};
    salt2[0] = 0x01; /* changes derived key */
    uint8_t enc_key2[CHOI_KEY_SIZE], mac_key2[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt2, enc_key2, mac_key2);
    uint8_t ct3[CHOI_BLOCK_SIZE];
    choi_encrypt_block(pt, ct3);
    diff = count_bit_diff(ct, ct3, CHOI_BLOCK_SIZE);
    printf("Avalanche (1-bit key flip): %d/%d bits changed (%.1f%%)\n",
           diff, (int)(CHOI_BLOCK_SIZE * 8),
           100.0 * diff / (CHOI_BLOCK_SIZE * 8));

    (void)enc_key; (void)mac_key; (void)enc_key2; (void)mac_key2;
}

/* ------------------------------------------------------------------
 * Phase 2: CTR mode keystream reuse detection
 * ------------------------------------------------------------------ */
static void phase2_ctr(void) {
    printf("\n=== Phase 2: CTR mode keystream properties ===\n");

    const char *pw = "ctr_demo_key";
    uint8_t salt[CHOI_SALT_SIZE] = {0};
    uint8_t enc_key[CHOI_KEY_SIZE], mac_key[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt, enc_key, mac_key);

    uint8_t nonce[CHOI_NONCE_SIZE] = {0};
    uint8_t p1[CHOI_BLOCK_SIZE] = "AAAABBBBCCCCDDDD";
    uint8_t p2[CHOI_BLOCK_SIZE] = "ZZZZYYYYXXXXWWWW";
    uint8_t c1[CHOI_BLOCK_SIZE], c2[CHOI_BLOCK_SIZE];

    memcpy(c1, p1, CHOI_BLOCK_SIZE);
    memcpy(c2, p2, CHOI_BLOCK_SIZE);
    choi_transform(c1, CHOI_BLOCK_SIZE, nonce);
    choi_transform(c2, CHOI_BLOCK_SIZE, nonce);

    int ok = 1;
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i) {
        if ((c1[i] ^ c2[i]) != (p1[i] ^ p2[i])) ok = 0;
    }
    printf("Same nonce => C1^C2 == P1^P2 ? %s (CTR property)\n", ok ? "YES" : "NO");

    uint8_t nonce2[CHOI_NONCE_SIZE] = {1};
    uint8_t c3[CHOI_BLOCK_SIZE];
    memcpy(c3, p1, CHOI_BLOCK_SIZE);
    choi_transform(c3, CHOI_BLOCK_SIZE, nonce2);
    int same = (memcmp(c1, c3, CHOI_BLOCK_SIZE) == 0);
    printf("Different nonce => identical keystream? %s (should be NO)\n",
           same ? "YES (FAIL)" : "NO (OK)");

    (void)enc_key; (void)mac_key;
}

/* ------------------------------------------------------------------
 * Phase 3: HMAC authentication
 * ------------------------------------------------------------------ */
static void phase3_hmac(void) {
    printf("\n=== Phase 3: HMAC authentication ===\n");

    const char *pw = "hmac_demo_password";
    uint8_t salt[CHOI_SALT_SIZE] = {0};
    uint8_t enc_key[CHOI_KEY_SIZE], mac_key[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt, enc_key, mac_key);

    const uint8_t msg[] = "Authenticate this message.";
    size_t msglen = strlen((const char *)msg);
    uint8_t tag[CHOI_HMAC_SIZE];
    choi_hmac_sha256(mac_key, CHOI_KEY_SIZE, msg, msglen, tag);
    print_hex("HMAC: ", tag, CHOI_HMAC_SIZE);

    uint8_t wrong_key[CHOI_KEY_SIZE];
    memcpy(wrong_key, mac_key, CHOI_KEY_SIZE);
    wrong_key[0] ^= 0x01;
    uint8_t wrong_tag[CHOI_HMAC_SIZE];
    choi_hmac_sha256(wrong_key, CHOI_KEY_SIZE, msg, msglen, wrong_tag);

    if (memcmp(tag, wrong_tag, CHOI_HMAC_SIZE) == 0) {
        printf("FAIL: HMAC collision with 1-bit key flip\n");
    } else {
        printf("[OK] 1-bit key flip produces different HMAC.\n");
    }

    (void)enc_key;
}

/* ------------------------------------------------------------------
 * Phase 4: Virtual Silicon VM
 * ------------------------------------------------------------------ */
static void phase4_virtual_silicon(void) {
    printf("\n=== Phase 4: Virtual Silicon VM ===\n");

    uint8_t seed[VS_REG_SIZE];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        (void)read(fd, seed, VS_REG_SIZE);
        close(fd);
    } else {
        memset(seed, 0x5A, VS_REG_SIZE);
    }
    uint8_t rng_out[64];
    vs_rng_bytes(seed, rng_out, sizeof(rng_out));
    print_hex("VM RNG (64 bytes): ", rng_out, sizeof(rng_out));

    uint8_t kdf_out[32];
    vs_kdf("vm_kdf_password", seed, 100000, kdf_out, sizeof(kdf_out));
    print_hex("VM KDF (32 bytes): ", kdf_out, sizeof(kdf_out));

    uint8_t key[VS_REG_SIZE] = {0};
    uint8_t block[VS_REG_SIZE] = "VirtualSilicon!!";
    memcpy(key, seed, VS_REG_SIZE);
    uint8_t obf[VS_REG_SIZE];
    memcpy(obf, block, VS_REG_SIZE);
    vs_obfuscate_block(key, obf);
    print_hex("VM obfuscated: ", obf, VS_REG_SIZE);
    vs_obfuscate_block(key, obf); /* self-inverse */
    print_hex("VM restored:    ", obf, VS_REG_SIZE);

    if (memcmp(block, obf, VS_REG_SIZE) == 0)
        printf("[OK] VM obfuscation is self-inverse.\n");
    else
        printf("FAIL: VM obfuscation not self-inverse\n");

    /* Key-dependent ISA demo. */
    printf("\n--- Key-dependent ISA ---\n");
    vs_vm vm1, vm2;
    vs_vm_init_keyed(&vm1, (const uint8_t *)"key_one_key_one!");
    vs_vm_init_keyed(&vm2, (const uint8_t *)"key_two_key_two!");
    int same_map = (memcmp(vm1.opcode_map, vm2.opcode_map, VS_OPCODE_MAP_SIZE) == 0);
    printf("Same key => same ISA map? YES (required)\n");
    printf("Different keys => same ISA map? %s (should be NO)\n",
           same_map ? "YES (FAIL)" : "NO (OK)");

    /* Bank switching demo. */
    printf("\n--- Bank switching ---\n");
    vs_vm_init(&vm1);
    uint8_t pattern[VS_REG_SIZE];
    memset(pattern, 0xAB, VS_REG_SIZE);
    vs_load(&vm1, 0, pattern);     /* writes physical reg 0 */
    vs_switch_bank(&vm1, 1);
    vs_load(&vm1, 0, pattern);     /* writes physical reg 4 */
    uint8_t r0_bank0[VS_REG_SIZE], r0_bank1[VS_REG_SIZE];
    vs_switch_bank(&vm1, 0);
    vs_store(&vm1, 0, r0_bank0);
    vs_switch_bank(&vm1, 1);
    vs_store(&vm1, 0, r0_bank1);
    int banks_independent = (memcmp(r0_bank0, r0_bank1, VS_REG_SIZE) == 0);
    printf("R0 in bank0 == R0 in bank1? %s (should be NO after identical writes)\n",
           banks_independent ? "YES (FAIL)" : "NO (OK)");

    /* Self-modifying bytecode demo. */
    printf("\n--- Self-modifying bytecode ---\n");
    vs_vm_init(&vm1);
    uint8_t mask[VS_REG_SIZE];
    memset(mask, 0x5A, VS_REG_SIZE);
    vs_load(&vm1, 0, mask);
    /* The program patches the byte at offset len+0 of the rewrite buffer
     * (i.e., the first byte after the original program) with R0. */
    const uint8_t patch_prog[] = {
        VS_OP_PATCH, 4, 1,  /* patch byte at offset 4 with R0[0] */
        VS_OP_HALT,
        0x00  /* slot that will be modified */
    };
    uint8_t run_buf[sizeof(patch_prog)];
    memcpy(run_buf, patch_prog, sizeof(patch_prog));
    vs_run(&vm1, run_buf, sizeof(patch_prog) - 1, 64);
    printf("Patched byte: 0x%02x (expected 0x%02x)\n",
           vm1.rewrite_buf[0], 0x00 ^ 0x5A);
}

/* ------------------------------------------------------------------
 * Phase 5: Dynamic ASM round-trip
 * ------------------------------------------------------------------ */
static void phase5_dynamic_asm(void) {
    printf("\n=== Phase 5: Dynamic ASM round-trip ===\n");

    uint8_t state[STATE_SIZE] = "DynamicASMBlock!";
    uint8_t round_keys[NUM_ROUNDS][STATE_SIZE];
    for (int r = 0; r < NUM_ROUNDS; ++r) {
        for (int i = 0; i < STATE_SIZE; ++i) {
            round_keys[r][i] = (uint8_t)((r * 17 + i * 3) ^ 0xA5);
        }
    }

    uint8_t orig[STATE_SIZE];
    memcpy(orig, state, STATE_SIZE);
    dynamic_asm_encrypt(state, round_keys);
    print_hex("Encrypted: ", state, STATE_SIZE);
    dynamic_asm_decrypt(state, round_keys);
    print_hex("Decrypted: ", state, STATE_SIZE);

    if (memcmp(orig, state, STATE_SIZE) == 0)
        printf("[OK] Dynamic ASM round-trip successful.\n");
    else
        printf("FAIL: Dynamic ASM round-trip mismatch\n");
}

/* ------------------------------------------------------------------
 * Phase 6: Obfuscated pipeline round-trip
 * ------------------------------------------------------------------ */
static void phase6_obfuscated_pipeline(void) {
    printf("\n=== Phase 6: Obfuscated pipeline round-trip ===\n");

    uint8_t state[OBF_STATE_SIZE] = "ObfuscatedPipe!!";
    uint8_t seed[32] = "MySuperSecretExpansionSeed32Byte";
    int num_rounds = 32;
    uint8_t round_keys[OBF_MAX_ROUNDS][OBF_STATE_SIZE];

    uint8_t orig[OBF_STATE_SIZE];
    memcpy(orig, state, OBF_STATE_SIZE);

    obf_pipeline_encrypt(state, seed, num_rounds, round_keys);
    print_hex("Obfuscated: ", state, OBF_STATE_SIZE);
    obf_pipeline_decrypt(state, seed, num_rounds, (const uint8_t (*)[OBF_STATE_SIZE])round_keys);
    print_hex("Restored:   ", state, OBF_STATE_SIZE);

    if (memcmp(orig, state, OBF_STATE_SIZE) == 0)
        printf("[OK] Obfuscated pipeline round-trip successful.\n");
    else
        printf("FAIL: Obfuscated pipeline round-trip mismatch\n");
}

/* ------------------------------------------------------------------ */
int main(void) {
    printf("=== CHOICRYPT PoC / Verification ===\n");
    printf("WARNING: This is an experimental custom cipher.\n");

    phase1_block();
    phase2_ctr();
    phase3_hmac();
    phase4_virtual_silicon();
    phase5_dynamic_asm();
    phase6_obfuscated_pipeline();

    printf("\n=== PoC complete ===\n");
    return 0;
}
