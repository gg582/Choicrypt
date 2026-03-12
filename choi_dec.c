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

    const char *input_path = argv[1];
    size_t input_len = strlen(argv[1]);
    char *resolved_path = NULL;
    if (input_len < 5 || strcmp(argv[1] + input_len - 5, ".choi") != 0) {
        resolved_path = malloc(input_len + 6);
        if (!resolved_path) return 1;
        snprintf(resolved_path, input_len + 6, "%s.choi", argv[1]);
        FILE *probe = fopen(resolved_path, "rb");
        if (probe) {
            fclose(probe);
            input_path = resolved_path;
        }
    }

    FILE *f = fopen(input_path, "rb");
    if (!f) {
        free(resolved_path);
        return perror("fopen"), 1;
    }

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);

    if (len < 4) {
        fprintf(stderr, "Invalid file.\n");
        fclose(f);
        free(resolved_path);
        return 1;
    }

    uint8_t *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    transform(buf, len);

    size_t data_len = len - 4;
    uint32_t expected_cs = calculate_checksum(buf, data_len);
    uint32_t read_cs = (buf[data_len] << 24) | (buf[data_len+1] << 16) | (buf[data_len+2] << 8) | buf[data_len+3];

    FILE *out = fopen(argv[2], "wb");
    if (expected_cs == read_cs) {
        fwrite(buf, 1, data_len, out);
    } else {
        // Incorrect key: generate decoy text
        uint8_t *decoy = malloc(data_len);
        generate_decoy((const uint8_t *)pw, data_len, decoy);
        fwrite(decoy, 1, data_len, out);
        free(decoy);
    }
    fclose(out);

    free(resolved_path);
    free(buf);
    return 0;
}
