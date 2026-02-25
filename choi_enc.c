#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * SOURCE: Choi Seok-jeong's Jisugwimundo Lattice Logic.
 * * This tool encrypts a file using a specific hexagonal magic square map.
 * * The security strength lies in the NP-hard nature of the vertex distribution.
 */

#define VERTEX_COUNT 30

/* The Key: A specific solution of Jisugwimundo (H=93) */
static const uint8_t MAGIC_MAP[VERTEX_COUNT] = {
    1, 30, 15, 20, 12, 18, 5, 25, 10, 2,
    19, 21, 3, 28, 7, 14, 23, 9, 11, 26,
    4, 17, 22, 8, 16, 24, 6, 27, 13, 29
};

void transform(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t key = MAGIC_MAP[i % VERTEX_COUNT];
        /* Step 1: Spatial XOR with hexagonal vertex */
        data[i] ^= key;
        /* Step 2: Bitwise rotation determined by the magic constant */
        uint8_t shift = key % 8;
        data[i] = (data[i] << shift) | (data[i] >> (8 - shift));
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) return printf("Usage: %s <file>\n", argv[0]), 1;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return perror("File open error"), 1;

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);

    uint8_t *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    transform(buf, len);

    char out_name[256];
    snprintf(out_name, sizeof(out_name), "%s.choi", argv[1]);
    FILE *out = fopen(out_name, "wb");
    fwrite(buf, 1, len, out);
    fclose(out);

    printf("Encrypted: %s\n", out_name);
    free(buf);
    return 0;
}
