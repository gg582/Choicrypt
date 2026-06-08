#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "choi_common.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: echo 'pw' | %s <file>\n", argv[0]);
        return 1;
    }

    char pw[256];
    if (scanf("%255s", pw) != 1) return 1;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return perror("fopen"), 1;

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);

    uint8_t *plain = malloc(len);
    if (!plain) { fclose(f); return perror("malloc"), 1; }
    fread(plain, 1, len, f);
    fclose(f);

    uint8_t nonce[NONCE_SIZE];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, nonce, NONCE_SIZE) != NONCE_SIZE) {
        fprintf(stderr, "Failed to read nonce\n");
        free(plain);
        return 1;
    }
    close(fd);

    uint8_t enc_key[32], mac_key[32];
    derive_keys(pw, nonce, NONCE_SIZE, enc_key, mac_key);

    uint8_t hmac[HMAC_SIZE];
    hmac_sha256(mac_key, 32, plain, len, hmac);

    uint8_t *payload = malloc(len + HMAC_SIZE);
    if (!payload) { free(plain); return perror("malloc"), 1; }
    memcpy(payload, plain, len);
    memcpy(payload + len, hmac, HMAC_SIZE);

    transform(payload, len + HMAC_SIZE, nonce);

    char out_name[512];
    snprintf(out_name, sizeof(out_name), "%s.choi", argv[1]);
    FILE *out = fopen(out_name, "wb");
    fwrite(nonce, 1, NONCE_SIZE, out);
    fwrite(payload, 1, len + HMAC_SIZE, out);
    fclose(out);

    free(plain);
    free(payload);
    return 0;
}
