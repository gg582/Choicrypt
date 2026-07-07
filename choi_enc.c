/*
 * choi_enc.c — Choicrypt file encryption tool
 *
 * File format:
 *   [16-byte salt][16-byte nonce][ciphertext][32-byte HMAC-SHA256]
 *
 * The ciphertext is produced by CTR-mode XOR of (plaintext || HMAC).
 * The HMAC is computed over the original plaintext with the derived MAC key.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "choi_common.h"

#define CHOI_SUFFIX ".choi"

static int read_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t total = 0;
    while ((size_t)total < len) {
        ssize_t n = read(fd, buf + total, len - (size_t)total);
        if (n <= 0) { close(fd); return -1; }
        total += n;
    }
    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: echo 'password' | %s <file>\n", argv[0]);
        return 1;
    }

    char pw[256];
    if (scanf("%255s", pw) != 1) {
        fprintf(stderr, "Failed to read password\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }
    long flen = ftell(f);
    if (flen < 0) {
        perror("ftell");
        fclose(f);
        return 1;
    }
    size_t len = (size_t)flen;
    rewind(f);

    uint8_t *plain = (uint8_t *)malloc(len);
    if (!plain) {
        perror("malloc");
        fclose(f);
        return 1;
    }
    if (fread(plain, 1, len, f) != len) {
        fprintf(stderr, "Failed to read input file\n");
        free(plain);
        fclose(f);
        return 1;
    }
    fclose(f);

    uint8_t salt[CHOI_SALT_SIZE];
    uint8_t nonce[CHOI_NONCE_SIZE];
    if (read_random(salt, CHOI_SALT_SIZE) != 0 ||
        read_random(nonce, CHOI_NONCE_SIZE) != 0) {
        fprintf(stderr, "Failed to gather random salt/nonce\n");
        free(plain);
        return 1;
    }

    uint8_t enc_key[CHOI_KEY_SIZE], mac_key[CHOI_KEY_SIZE];
    choi_derive_keys(pw, salt, enc_key, mac_key);

    uint8_t hmac[CHOI_HMAC_SIZE];
    choi_hmac_sha256(mac_key, CHOI_KEY_SIZE, plain, len, hmac);

    size_t payload_len = len + CHOI_HMAC_SIZE;
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) {
        perror("malloc");
        free(plain);
        return 1;
    }
    memcpy(payload, plain, len);
    memcpy(payload + len, hmac, CHOI_HMAC_SIZE);

    choi_transform(payload, payload_len, nonce);

    char out_name[512];
    snprintf(out_name, sizeof(out_name), "%s%s", argv[1], CHOI_SUFFIX);
    FILE *out = fopen(out_name, "wb");
    if (!out) {
        perror("fopen");
        free(plain);
        free(payload);
        return 1;
    }

    if (fwrite(salt, 1, CHOI_SALT_SIZE, out) != CHOI_SALT_SIZE ||
        fwrite(nonce, 1, CHOI_NONCE_SIZE, out) != CHOI_NONCE_SIZE ||
        fwrite(payload, 1, payload_len, out) != payload_len) {
        fprintf(stderr, "Failed to write output file\n");
        fclose(out);
        free(plain);
        free(payload);
        return 1;
    }
    fclose(out);

    /* Wipe sensitive stack data. */
    memset(pw, 0, sizeof(pw));
    memset(enc_key, 0, sizeof(enc_key));
    memset(mac_key, 0, sizeof(mac_key));
    free(plain);
    free(payload);
    return 0;
}
