/*
 * test_honey.c — Unit tests for decoy generation
 *
 * The decoy mode is experimental and NOT full Honey Encryption.
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
    printf("=== test_honey ===\n");

    uint8_t ct[64];
    for (int i = 0; i < 64; ++i) ct[i] = (uint8_t)(i * 11 + 7);

    uint8_t decoy1[64], decoy2[64];
    choi_generate_decoy(ct, sizeof(ct), decoy1, sizeof(decoy1));
    choi_generate_decoy(ct, sizeof(ct), decoy2, sizeof(decoy2));

    /* 1. Decoy is deterministic for the same ciphertext. */
    ASSERT(memcmp(decoy1, decoy2, sizeof(decoy1)) == 0,
           "decoy is deterministic for a given ciphertext");

    /* 2. Decoy differs from the original ciphertext. */
    ASSERT(memcmp(decoy1, ct, sizeof(ct)) != 0,
           "decoy differs from ciphertext");

    /* 3. Different ciphertext yields different decoy. */
    uint8_t ct2[64];
    memcpy(ct2, ct, 64);
    ct2[0] ^= 0x01;
    uint8_t decoy3[64];
    choi_generate_decoy(ct2, sizeof(ct2), decoy3, sizeof(decoy3));
    ASSERT(memcmp(decoy1, decoy3, sizeof(decoy1)) != 0,
           "different ciphertext yields different decoy");

    if (failures == 0) printf("All decoy tests passed.\n");
    else printf("%d test(s) failed.\n", failures);
    return failures ? 1 : 0;
}
