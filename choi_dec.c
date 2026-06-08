#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "choi_common.h"

#define CHOI_SUFFIX ".choi"
#define CHOI_SUFFIX_LEN 5

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: echo 'pw' | %s <in> <out>\n", argv[0]);
        return 1;
    }

    char pw[256];
    if (scanf("%255s", pw) != 1) return 1;

    const char *input_path = argv[1];
    size_t input_len = strlen(argv[1]);
    char *resolved_path = NULL;
    if (input_len < CHOI_SUFFIX_LEN || strcmp(argv[1] + input_len - CHOI_SUFFIX_LEN, CHOI_SUFFIX) != 0) {
        resolved_path = malloc(input_len + CHOI_SUFFIX_LEN + 1);
        if (!resolved_path) return perror("malloc"), 1;
        snprintf(resolved_path, input_len + CHOI_SUFFIX_LEN + 1, "%s%s", argv[1], CHOI_SUFFIX);
        FILE *probe = fopen(resolved_path, "rb");
        if (probe) {
            fclose(probe);
            input_path = resolved_path;
        } else {
            free(resolved_path);
            resolved_path = NULL;
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

    if (len < NONCE_SIZE + HMAC_SIZE) {
        fprintf(stderr, "Invalid file.\n");
        fclose(f);
        free(resolved_path);
        return 1;
    }

    uint8_t nonce[NONCE_SIZE];
    if (fread(nonce, 1, NONCE_SIZE, f) != NONCE_SIZE) {
        fclose(f);
        free(resolved_path);
        return 1;
    }

    size_t ct_len = len - NONCE_SIZE;
    uint8_t *ct = malloc(ct_len);
    if (!ct) {
        fclose(f);
        free(resolved_path);
        return perror("malloc"), 1;
    }
    fread(ct, 1, ct_len, f);
    fclose(f);

    uint8_t enc_key[32], mac_key[32];
    derive_keys(pw, nonce, NONCE_SIZE, enc_key, mac_key);

    transform(ct, ct_len, nonce);

    size_t plain_len = ct_len - HMAC_SIZE;
    uint8_t *plain = ct;
    uint8_t *read_hmac = ct + plain_len;

    uint8_t expected_hmac[HMAC_SIZE];
    hmac_sha256(mac_key, 32, plain, plain_len, expected_hmac);

    FILE *out = fopen(argv[2], "wb");
    if (memcmp(expected_hmac, read_hmac, HMAC_SIZE) == 0) {
        fwrite(plain, 1, plain_len, out);
    } else {
        uint8_t *decoy = malloc(plain_len);
        generate_secure_decoy(mac_key, plain_len, decoy);
        fwrite(decoy, 1, plain_len, out);
        free(decoy);
    }
    fclose(out);

    free(resolved_path);
    free(ct);
    return 0;
}
