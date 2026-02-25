#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * SOURCE: Choi Seok-jeong's Jisugwimundo Inverse Filter.
 * * Reverses the hexagonal rotation and XOR operation.
 */

#define VERTEX_COUNT 30

static const uint8_t MAGIC_MAP[VERTEX_COUNT] = {
    1, 30, 15, 20, 12, 18, 5, 25, 10, 2,
    19, 21, 3, 28, 7, 14, 23, 9, 11, 26,
    4, 17, 22, 8, 16, 24, 6, 27, 13, 29
};

void inverse_transform(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t key = MAGIC_MAP[i % VERTEX_COUNT];
        /* Step 1: Reverse Bitwise rotation */
        uint8_t shift = key % 8;
        data[i] = (data[i] >> shift) | (data[i] << (8 - shift));
        /* Step 2: Spatial XOR with hexagonal vertex */
        data[i] ^= key;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) return printf("Usage: %s <file.choi>\n", argv[0]), 1;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return perror("File open error"), 1;

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);

    uint8_t *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    inverse_transform(buf, len);

    /* Output to stdout for streaming or pipe */
    fwrite(buf, 1, len, stdout);

    free(buf);
    return 0;
}
