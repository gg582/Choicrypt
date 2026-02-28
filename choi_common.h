#ifndef CHOI_COMMON_H
#define CHOI_COMMON_H

#include <stdint.h>
#include <string.h>

#define VERTEX_COUNT 30

/* Base Jisugwimundo solution (H=93) */
static uint8_t MAGIC_MAP[VERTEX_COUNT] = {
    1, 30, 15, 20, 12, 18, 5, 25, 10, 2,
    19, 21, 3, 28, 7, 14, 23, 9, 11, 26,
    4, 17, 22, 8, 16, 24, 6, 27, 13, 29
};

/* Deterministic Fisher-Yates shuffle based on password seed */
static void derive_key(const char *pw) {
    uint32_t seed = 5381;
    while (*pw) seed = ((seed << 5) + seed) + *pw++;
    
    for (int i = VERTEX_COUNT - 1; i > 0; i--) {
        seed = (seed * 1103515245 + 12345);
        int j = (seed >> 16) % (i + 1);
        uint8_t temp = MAGIC_MAP[i];
        MAGIC_MAP[i] = MAGIC_MAP[j];
        MAGIC_MAP[j] = temp;
    }
}

/* Bi-directional transformation: XOR + Bitwise Rotation */
static void transform(uint8_t *data, size_t len, int encrypt) {
    for (size_t i = 0; i < len; i++) {
        uint8_t key = MAGIC_MAP[i % VERTEX_COUNT];
        uint8_t shift = key % 8;
        if (encrypt) {
            data[i] ^= key;
            data[i] = (data[i] << shift) | (data[i] >> (8 - shift));
        } else {
            data[i] = (data[i] >> shift) | (data[i] << (8 - shift));
            data[i] ^= key;
        }
    }
}

#endif
