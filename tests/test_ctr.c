/*
 * test_ctr.c — Unit tests for CTR mode transform
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

int main(void) {
    printf("=== test_ctr ===\n");

    const char *pw = "ctr_test_password";
    uint8_t salt[CHOI_SALT_SIZE] = {0};
    uint8_t enc_key[CHOI_KEY_SIZE], mac_key[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt, enc_key, mac_key);

    /* 1. Round-trip on a multi-block buffer. */
    uint8_t plain[64];
    for (int i = 0; i < 64; ++i) plain[i] = (uint8_t)(i * 7 + 13);
    uint8_t buf[64];
    memcpy(buf, plain, 64);

    uint8_t nonce[CHOI_NONCE_SIZE] = {0};
    choi_transform(buf, 64, nonce);
    ASSERT(memcmp(buf, plain, 64) != 0, "transform changes data");

    choi_transform(buf, 64, nonce);
    ASSERT(memcmp(buf, plain, 64) == 0, "double transform recovers data");

    /* 2. Different nonce produces different ciphertext. */
    uint8_t buf2[64];
    memcpy(buf2, plain, 64);
    uint8_t nonce2[CHOI_NONCE_SIZE] = {1, 0};
    choi_transform(buf2, 64, nonce2);
    ASSERT(memcmp(buf, buf2, 64) != 0, "different nonce -> different output");

    /* 3. CTR property: same nonce => C1^C2 == P1^P2. */
    uint8_t p1[CHOI_BLOCK_SIZE] = "AAAABBBBCCCCDDDD";
    uint8_t p2[CHOI_BLOCK_SIZE] = "ZZZZYYYYXXXXWWWW";
    uint8_t c1[CHOI_BLOCK_SIZE], c2[CHOI_BLOCK_SIZE];
    memcpy(c1, p1, CHOI_BLOCK_SIZE);
    memcpy(c2, p2, CHOI_BLOCK_SIZE);
    choi_transform(c1, CHOI_BLOCK_SIZE, nonce);
    choi_transform(c2, CHOI_BLOCK_SIZE, nonce);
    int ctr_ok = 1;
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i)
        if ((c1[i] ^ c2[i]) != (p1[i] ^ p2[i])) ctr_ok = 0;
    ASSERT(ctr_ok, "CTR keystream property holds");

    /* 4. Counter does not overflow in 3 blocks. */
    uint8_t big[CHOI_BLOCK_SIZE * 3];
    memset(big, 0xAB, sizeof(big));
    uint8_t nonce3[CHOI_NONCE_SIZE] = {0};
    /* Set last nonce bytes near wrap to exercise increment. */
    nonce3[CHOI_NONCE_SIZE - 1] = 0xFE;
    choi_transform(big, sizeof(big), nonce3);
    choi_transform(big, sizeof(big), nonce3);
    int all_ab = 1;
    for (size_t i = 0; i < sizeof(big); ++i) if (big[i] != 0xAB) all_ab = 0;
    ASSERT(all_ab, "counter increment over multiple blocks is reversible");

    (void)enc_key; (void)mac_key;

    if (failures == 0) printf("All CTR tests passed.\n");
    else printf("%d test(s) failed.\n", failures);
    return failures ? 1 : 0;
}
