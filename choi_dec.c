/*
 * choi_dec.c — Choicrypt file decryption tool
 *
 * File format:
 *   [16-byte salt][16-byte nonce][ciphertext][32-byte HMAC-SHA256]
 *
 * Default behaviour on HMAC mismatch: report failure and write nothing.
 * With --decoy, output a deterministic decoy instead (experimental).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "choi_common.h"

#define CHOI_SUFFIX ".choi"
#define CHOI_SUFFIX_LEN 5

int main(int argc, char *argv[]) {
    int use_decoy = 0;
    int argoff = 1;

    if (argc > 1 && strcmp(argv[1], "--decoy") == 0) {
        use_decoy = 1;
        argoff = 2;
    }

    if (argc - argoff < 2) {
        fprintf(stderr, "Usage: echo 'password' | %s [--decoy] <in> <out>\n", argv[0]);
        return 1;
    }

    char pw[256];
    if (scanf("%255s", pw) != 1) {
        fprintf(stderr, "Failed to read password\n");
        return 1;
    }

    const char *input_arg = argv[argoff];
    const char *output_arg = argv[argoff + 1];

    /* Allow omitting the .choi extension. */
    size_t input_len = strlen(input_arg);
    char *resolved_path = NULL;
    const char *input_path = input_arg;
    if (input_len < CHOI_SUFFIX_LEN ||
        strcmp(input_arg + input_len - CHOI_SUFFIX_LEN, CHOI_SUFFIX) != 0) {
        resolved_path = (char *)malloc(input_len + CHOI_SUFFIX_LEN + 1);
        if (!resolved_path) {
            perror("malloc");
            return 1;
        }
        snprintf(resolved_path, input_len + CHOI_SUFFIX_LEN + 1,
                 "%s%s", input_arg, CHOI_SUFFIX);
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
        perror("fopen");
        free(resolved_path);
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        free(resolved_path);
        return 1;
    }
    long flen = ftell(f);
    if (flen < 0) {
        perror("ftell");
        fclose(f);
        free(resolved_path);
        return 1;
    }
    size_t file_len = (size_t)flen;
    rewind(f);

    if (file_len < CHOI_SALT_SIZE + CHOI_NONCE_SIZE + CHOI_HMAC_SIZE) {
        fprintf(stderr, "Invalid file: too short.\n");
        fclose(f);
        free(resolved_path);
        return 1;
    }

    uint8_t salt[CHOI_SALT_SIZE];
    uint8_t nonce[CHOI_NONCE_SIZE];
    if (fread(salt, 1, CHOI_SALT_SIZE, f) != CHOI_SALT_SIZE ||
        fread(nonce, 1, CHOI_NONCE_SIZE, f) != CHOI_NONCE_SIZE) {
        fprintf(stderr, "Failed to read header.\n");
        fclose(f);
        free(resolved_path);
        return 1;
    }

    size_t ct_len = file_len - CHOI_SALT_SIZE - CHOI_NONCE_SIZE;
    uint8_t *ct = (uint8_t *)malloc(ct_len);
    if (!ct) {
        perror("malloc");
        fclose(f);
        free(resolved_path);
        return 1;
    }
    if (fread(ct, 1, ct_len, f) != ct_len) {
        fprintf(stderr, "Failed to read ciphertext.\n");
        free(ct);
        fclose(f);
        free(resolved_path);
        return 1;
    }
    fclose(f);

    uint8_t enc_key[CHOI_KEY_SIZE], mac_key[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt, enc_key, mac_key);

    choi_transform(ct, ct_len, nonce);

    size_t plain_len = ct_len - CHOI_HMAC_SIZE;
    uint8_t *plain = ct;
    uint8_t *read_hmac = ct + plain_len;

    uint8_t expected_hmac[CHOI_HMAC_SIZE];
    choi_hmac_sha256(mac_key, CHOI_KEY_SIZE, plain, plain_len, expected_hmac);

    FILE *out = fopen(output_arg, "wb");
    if (!out) {
        perror("fopen");
        free(ct);
        free(resolved_path);
        return 1;
    }

    int hmac_ok = (memcmp(expected_hmac, read_hmac, CHOI_HMAC_SIZE) == 0);
    if (hmac_ok) {
        if (fwrite(plain, 1, plain_len, out) != plain_len) {
            fprintf(stderr, "Failed to write plaintext.\n");
            fclose(out);
            free(ct);
            free(resolved_path);
            return 1;
        }
    } else if (use_decoy) {
        uint8_t *decoy = (uint8_t *)malloc(plain_len);
        if (!decoy) {
            perror("malloc");
            fclose(out);
            free(ct);
            free(resolved_path);
            return 1;
        }
        choi_generate_decoy(ct, ct_len, decoy, plain_len);
        if (fwrite(decoy, 1, plain_len, out) != plain_len) {
            fprintf(stderr, "Failed to write decoy.\n");
            fclose(out);
            free(decoy);
            free(ct);
            free(resolved_path);
            return 1;
        }
        free(decoy);
        fprintf(stderr, "[decoy] HMAC mismatch — decoy output generated.\n");
    } else {
        fprintf(stderr, "Authentication failed: wrong password or corrupted file.\n");
        fclose(out);
        /* Remove the empty/incorrect output file if possible. */
        remove(output_arg);
        free(ct);
        free(resolved_path);
        memset(pw, 0, sizeof(pw));
        memset(enc_key, 0, sizeof(enc_key));
        memset(mac_key, 0, sizeof(mac_key));
        return 1;
    }

    fclose(out);
    free(ct);
    free(resolved_path);
    memset(pw, 0, sizeof(pw));
    memset(enc_key, 0, sizeof(enc_key));
    memset(mac_key, 0, sizeof(mac_key));
    return 0;
}
