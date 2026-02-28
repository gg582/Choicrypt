#include <stdio.h>
#include <stdlib.h>
#include "choi_common.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: echo 'pw' | %s <in> <out>\n", argv[0]);
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

    uint8_t *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    transform(buf, len, 0);

    FILE *out = fopen(argv[2], "wb");
    fwrite(buf, 1, len, out);
    fclose(out);

    free(buf);
    return 0;
}
