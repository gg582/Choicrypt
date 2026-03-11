#include <stdio.h>
#include <stdlib.h>
#include "choi_common.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: echo 'pw' | %s <file>\n", argv[0]);
        return 1;
    }

    char pw[256];
    if (scanf("%255s", pw) != 1) return 1;

    derive_key(pw);

    FILE *f = fopen(argv[1], "rb");
    if (!f) return perror("fopen"), 1;

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);

    // Buffer for data + 4 bytes checksum
    uint8_t *buf = malloc(len + 4);
    fread(buf, 1, len, f);
    fclose(f);

    // Calculate and append checksum
    uint32_t checksum = calculate_checksum(buf, len);
    buf[len] = (checksum >> 24) & 0xFF;
    buf[len+1] = (checksum >> 16) & 0xFF;
    buf[len+2] = (checksum >> 8) & 0xFF;
    buf[len+3] = checksum & 0xFF;

    transform(buf, len + 4);

    char out_name[512];
    snprintf(out_name, sizeof(out_name), "%s.choi", argv[1]);
    FILE *out = fopen(out_name, "wb");
    fwrite(buf, 1, len + 4, out);
    fclose(out);

    free(buf);
    return 0;
}
