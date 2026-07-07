/*
 * test_block.c — Unit tests for the Choicrypt block cipher
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../choi_common.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("[FAIL] %s\n", msg); \
        failures++; \
    } else { \
        printf("[OK]   %s\n", msg); \
    } \
} while (0)

static int count_bits(uint8_t x) {
    int n = 0;
    while (x) { n += x & 1; x >>= 1; }
    return n;
}

int main(void) {
    printf("=== test_block ===\n");

    const char *pw = "block_test_password";
    uint8_t salt[CHOI_SALT_SIZE] = {0};
    uint8_t enc_key[CHOI_KEY_SIZE], mac_key[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt, enc_key, mac_key);

    /* 1. Basic round-trip. */
    uint8_t pt[CHOI_BLOCK_SIZE] = "BlockCipherTest!";
    uint8_t ct[CHOI_BLOCK_SIZE], dec[CHOI_BLOCK_SIZE];
    choi_encrypt_block(pt, ct);
    choi_decrypt_block(ct, dec);
    ASSERT(memcmp(pt, dec, CHOI_BLOCK_SIZE) == 0,
           "encrypt->decrypt round-trip");

    /* 2. Ciphertext differs from plaintext. */
    ASSERT(memcmp(pt, ct, CHOI_BLOCK_SIZE) != 0,
           "ciphertext is not equal to plaintext");

    /* 3. S-Box is a bijection. */
    int sbox_bijection = 1;
    uint8_t inv_check[256];
    memset(inv_check, 0, 256);
    for (int i = 0; i < 256; ++i) inv_check[CHOI_SBOX[i]] = 1;
    for (int i = 0; i < 256; ++i) if (!inv_check[i]) sbox_bijection = 0;
    ASSERT(sbox_bijection, "dynamic S-Box is a bijection");

    /* 4. Avalanche: 1-bit plaintext change. */
    uint8_t pt2[CHOI_BLOCK_SIZE];
    memcpy(pt2, pt, CHOI_BLOCK_SIZE);
    pt2[0] ^= 0x01;
    uint8_t ct2[CHOI_BLOCK_SIZE];
    choi_encrypt_block(pt2, ct2);
    int diff = 0;
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i) diff += count_bits(ct[i] ^ ct2[i]);
    ASSERT(diff >= 4 && diff <= 124,
           "avalanche under plaintext bit-flip is in reasonable range");

    /* 5. Avalanche: 1-bit key change. */
    uint8_t salt2[CHOI_SALT_SIZE] = {0};
    salt2[0] = 0x01;
    uint8_t enc_key2[CHOI_KEY_SIZE], mac_key2[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt2, enc_key2, mac_key2);
    uint8_t ct3[CHOI_BLOCK_SIZE];
    choi_encrypt_block(pt, ct3);
    diff = 0;
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i) diff += count_bits(ct[i] ^ ct3[i]);
    ASSERT(diff >= 32 && diff <= 96,
           "avalanche under key bit-flip is in reasonable range");

    (void)enc_key; (void)mac_key; (void)enc_key2; (void)mac_key2;

    if (failures == 0) printf("All block tests passed.\n");
    else printf("%d test(s) failed.\n", failures);
    return failures ? 1 : 0;
}
