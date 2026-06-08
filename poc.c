#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "choi_common.h"

int is_decoy(const uint8_t *buf, size_t len) {
    const char *phrases[] = {
        "Access granted.",
        "Initialize sequence",
        "System stable.",
        "Protocol bypass active.",
        "Entropy verified."
    };
    for (int i = 0; i < 5; i++) {
        if (memmem(buf, len, phrases[i], strlen(phrases[i]))) return 1;
    }
    return 0;
}

int try_key(const char *pw, uint8_t *cipher, size_t len, uint8_t *out) {
    derive_key(pw);
    memcpy(out, cipher, len);
    transform(out, len);
    size_t dlen = len - 4;
    uint32_t expected = calculate_checksum(out, dlen);
    uint32_t read_cs = (out[dlen] << 24) | (out[dlen+1] << 16) | (out[dlen+2] << 8) | out[dlen+3];
    if (expected == read_cs) return 1;
    generate_decoy((const uint8_t *)pw, dlen, out);
    return 0;
}

int main() {
    FILE *f = fopen("../.gittoken.choi", "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);
    uint8_t *cipher = malloc(len);
    fread(cipher, 1, len, f);
    fclose(f);

    printf("=== CHOICRYPT PoC ===\n");
    printf("[*] Target: .gittoken.choi (%zu bytes)\n\n", len);

    const char *dict[] = {
        "password","123456","secret","token","git","github","choi","admin",
        "root","qwerty","letmein","monkey","dragon","master","gittoken",
        "pat","ghp","access","key","test","default","pass","user","login",
        "choicrypt","safetest","yjlee","1234","0000","iloveyou","hello",
        "welcome","abc123","football","princess","sunshine","password1",
        "123123","admin123","login123","guest","user123","pass123",
        "github_pat","ghp_","token123","secret123","choi123"
    };
    int n = sizeof(dict)/sizeof(dict[0]);
    printf("[*] Phase 1: Dictionary + Decoy Oracle (%d candidates)\n", n);
    int found = 0;
    for (int i = 0; i < n; i++) {
        uint8_t *tmp = malloc(len);
        int ok = try_key(dict[i], cipher, len, tmp);
        if (ok) {
            printf("[!!!] CRC MATCH: key='%s'\n", dict[i]);
            printf("      Plaintext: %.*s\n", (int)(len-4), tmp);
            found = 1;
        }
        free(tmp);
    }
    if (!found) printf("[*] No key recovered.\n");

    printf("\n[*] Phase 2: Decoy Distinguishing (Honey Encryption bypass)\n");
    int decoy_cnt = 0;
    for (int i = 0; i < 20; i++) {
        char rnd[32];
        snprintf(rnd, sizeof(rnd), "random%dtest", i * 7919);
        uint8_t *tmp = malloc(len);
        try_key(rnd, cipher, len, tmp);
        if (is_decoy(tmp, len-4)) decoy_cnt++;
        free(tmp);
    }
    printf("    20 random keys -> %d decoys.\n", decoy_cnt);
    printf("    -> Attacker filters decoy by phrase match; brute-force feasible.\n");

    printf("\n[*] Phase 3: Keystream Reuse (Fixed IV)\n");
    derive_key("fixed_iv_demo");
    uint8_t p1[16] = "AAAABBBBCCCCDDDD";
    uint8_t p2[16] = "ZZZZYYYYXXXXWWWW";
    uint8_t c1[16], c2[16];
    memcpy(c1, p1, 16); transform(c1, 16);
    memcpy(c2, p2, 16); transform(c2, 16);
    int reuse_ok = 1;
    for (int i = 0; i < 16; i++) if ((c1[i] ^ c2[i]) != (p1[i] ^ p2[i])) reuse_ok = 0;
    printf("    C1^C2 == P1^P2 ? %s\n", reuse_ok ? "YES (CRITICAL)" : "NO");

    printf("\n[*] Phase 4: Bit-flipping + CRC Forgery\n");
    derive_key("bitflip");
    char msg1[41] = "Legitimate admin token here for test!!!\n";
    uint32_t crc1 = calculate_checksum((uint8_t*)msg1, 41);
    uint8_t full1[45];
    memcpy(full1, msg1, 41);
    full1[41] = (crc1>>24)&0xFF; full1[42]=(crc1>>16)&0xFF; full1[43]=(crc1>>8)&0xFF; full1[44]=crc1&0xFF;
    uint8_t enc1[45];
    memcpy(enc1, full1, 45); transform(enc1, 45);

    char msg2[41] = "FORGED token here attacker controls!!!\n";
    uint32_t crc2 = calculate_checksum((uint8_t*)msg2, 41);
    uint8_t full2[45];
    memcpy(full2, msg2, 41);
    full2[41]=(crc2>>24)&0xFF; full2[42]=(crc2>>16)&0xFF; full2[43]=(crc2>>8)&0xFF; full2[44]=crc2&0xFF;

    uint8_t forged[45];
    for (int i = 0; i < 45; i++) forged[i] = enc1[i] ^ full1[i] ^ full2[i];

    uint8_t dec[45];
    memcpy(dec, forged, 45); transform(dec, 45);
    uint32_t rc = (dec[41]<<24)|(dec[42]<<16)|(dec[43]<<8)|dec[44];
    uint32_t ec = calculate_checksum(dec, 41);
    printf("    Decrypted forged msg: %.*s", 40, dec);
    printf("    CRC check: %s\n", (rc==ec)?"VALID (forgery accepted)":"INVALID");

    printf("\n[*] Phase 5: Crib-dragging on .gittoken.choi\n");
    printf("    Assumption: GitHub Classic PAT 'ghp_<36 chars>\\n' (41 bytes)\n");
    uint8_t crib[4] = {'g','h','p','_'};
    uint8_t ks[4];
    for (int i = 0; i < 4; i++) ks[i] = cipher[i] ^ crib[i];
    printf("    Recovered KS[0..3] if crib='ghp_': %02x %02x %02x %02x\n", ks[0], ks[1], ks[2], ks[3]);
    printf("    Decrypted prefix: ");
    for (int i = 0; i < 4; i++) putchar(cipher[i] ^ ks[i]);
    printf("\n");
    printf("    -> Multiple ciphertexts under same key expose full keystream.\n");

    free(cipher);
    return 0;
}
