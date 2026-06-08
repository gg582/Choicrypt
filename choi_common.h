#ifndef CHOI_COMMON_H
#define CHOI_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE 16
#define AES_NR 32
#define ROUND_KEY_WORDS (4 * (AES_NR + 1))
#define LARGE_PRIME 4294967279U
#define NONCE_SIZE 16
#define HMAC_SIZE 32

/* --- SHA-256 Implementation --- */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen; ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16; ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32; ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48; ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

static void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

static void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[32];
    const uint8_t *k = key;
    size_t kl = keylen;
    if (keylen > 64) {
        sha256(key, keylen, tk);
        k = tk; kl = 32;
    }
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < kl; i++) {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }
    SHA256_CTX ctx;
    uint8_t inner[32];
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, msg, msglen);
    sha256_final(&ctx, inner);
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

static void pbkdf2_hmac_sha256(const char *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t iter, uint8_t *out, size_t outlen) {
    size_t i = 1;
    size_t generated = 0;
    uint8_t *salt_i = malloc(saltlen + 4);
    while (generated < outlen) {
        size_t need = (outlen - generated < 32) ? (outlen - generated) : 32;
        memcpy(salt_i, salt, saltlen);
        salt_i[saltlen] = (i >> 24) & 0xFF;
        salt_i[saltlen+1] = (i >> 16) & 0xFF;
        salt_i[saltlen+2] = (i >> 8) & 0xFF;
        salt_i[saltlen+3] = i & 0xFF;
        uint8_t u[32], f[32];
        hmac_sha256((const uint8_t*)pw, pwlen, salt_i, saltlen + 4, u);
        memcpy(f, u, 32);
        for (uint32_t c = 1; c < iter; c++) {
            hmac_sha256((const uint8_t*)pw, pwlen, u, 32, u);
            for (int j = 0; j < 32; j++) f[j] ^= u[j];
        }
        memcpy(out + generated, f, need);
        generated += need;
        i++;
    }
    free(salt_i);
}

/* --- Cipher Core Logic (Preserved) --- */
static uint8_t DYNAMIC_SBOX[256];
static uint32_t ROUND_KEYS[ROUND_KEY_WORDS];
static int ENGINE_READY = 0;

static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static void generate_key_dep_sbox(const uint8_t *key_hash) {
    memcpy(DYNAMIC_SBOX, AES_SBOX, 256);
    uint32_t state = (key_hash[0] << 24) | (key_hash[1] << 16) | (key_hash[2] << 8) | key_hash[3];
    for (int i = 255; i > 0; i--) {
        state = (uint32_t)(((uint64_t)state * 1103515245u + 12345u) % LARGE_PRIME);
        uint32_t j = (state ^ key_hash[i % 32]) % (i + 1);
        uint8_t temp = DYNAMIC_SBOX[i];
        DYNAMIC_SBOX[i] = DYNAMIC_SBOX[j];
        DYNAMIC_SBOX[j] = temp;
    }
}

static const uint8_t HEX_ADJ[16][3] = {
    {1,5,15}, {0,2,6}, {1,3,7}, {2,4,8}, {3,5,9}, {4,0,10}, {1,7,11}, {2,6,12},
    {7,11,13}, {8,12,14}, {9,13,15}, {0,10,14}, {5,11,15}, {6,10,12}, {7,11,13}, {8,12,14}
};
#define MAGIC_SUM 93

static inline uint8_t rotl8(uint8_t value, int shift) {
    shift &= 7;
    return (uint8_t)((value << shift) | (value >> (8 - shift)));
}

static void hexagonal_refraction(uint8_t state[16], const uint8_t rk[16], int round_id) {
    for (int r = 0; r < 32; r++) {
        uint8_t next_state[16];
        for (int i = 0; i < 16; i++) {
            uint32_t z = state[i] + state[HEX_ADJ[i][0]] + state[HEX_ADJ[i][1]] + state[HEX_ADJ[i][2]];
            uint32_t c = (uint32_t)rk[i] ^ (uint32_t)round_id ^ (uint32_t)r ^ MAGIC_SUM;
            z = (uint32_t)(((uint64_t)z * z + c) % LARGE_PRIME);
            z = (uint32_t)(((uint64_t)z * z + c) % LARGE_PRIME);
            z = (uint32_t)(((uint64_t)z * z + c) % LARGE_PRIME);
            z = (uint32_t)(((uint64_t)z * z + c) % LARGE_PRIME);
            z = (uint32_t)(((uint64_t)z * z + c) % LARGE_PRIME);
            z = (uint32_t)(((uint64_t)z * z + c) % LARGE_PRIME);
            uint8_t val = (uint8_t)(z ^ (z >> 8) ^ (z >> 16) ^ (z >> 24));
            val = DYNAMIC_SBOX[val ^ rk[(i + r) % 16]];
            int shift = ((rk[i] + r + i) % 7) + 1;
            next_state[i] = rotl8(val, shift);
        }
        for (int i = 0; i < 16; i++) {
            uint8_t diff = next_state[i] ^ next_state[(i + 1) % 16];
            next_state[i] = DYNAMIC_SBOX[diff ^ (uint8_t)r];
        }
        for (int i = 0; i < 16; i++) {
            state[i] = DYNAMIC_SBOX[next_state[i] ^ rk[i] ^ (uint8_t)round_id];
        }
    }
}

static inline void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = DYNAMIC_SBOX[state[i]];
}

static inline void shift_rows(uint8_t state[16]) {
    uint8_t tmp;
    tmp = state[4]; state[4] = state[5]; state[5] = state[6]; state[6] = state[7]; state[7] = tmp;
    tmp = state[8]; uint8_t tmp2 = state[9]; state[8] = state[10]; state[9] = state[11]; state[10] = tmp; state[11] = tmp2;
    tmp = state[15]; state[15] = state[14]; state[14] = state[13]; state[13] = state[12]; state[12] = tmp;
}

static inline void add_round_key(uint8_t state[16], int round) {
    uint32_t *rk32 = &ROUND_KEYS[round * 4];
    for (int i = 0; i < 4; i++) {
        state[i*4]   ^= DYNAMIC_SBOX[(rk32[i] >> 24) & 0xFF];
        state[i*4+1] ^= DYNAMIC_SBOX[(rk32[i] >> 16) & 0xFF];
        state[i*4+2] ^= DYNAMIC_SBOX[(rk32[i] >> 8) & 0xFF];
        state[i*4+3] ^= DYNAMIC_SBOX[rk32[i] & 0xFF];
    }
}

static void choi_encrypt_block(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE]) {
    uint8_t state[16];
    memcpy(state, in, BLOCK_SIZE);
    add_round_key(state, 0);
    for (int round = 1; round < AES_NR; round++) {
        sub_bytes(state);
        shift_rows(state);
        uint8_t rk[16];
        uint32_t *rk32 = &ROUND_KEYS[round * 4];
        for (int i = 0; i < 4; i++) {
            rk[i*4]   = (rk32[i] >> 24) & 0xFF;
            rk[i*4+1] = (rk32[i] >> 16) & 0xFF;
            rk[i*4+2] = (rk32[i] >> 8) & 0xFF;
            rk[i*4+3] = rk32[i] & 0xFF;
        }
        hexagonal_refraction(state, rk, round);
        add_round_key(state, round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, AES_NR);
    for (int i = 0; i < 16; i++) {
        state[i] = DYNAMIC_SBOX[state[i] ^ (uint8_t)i ^ DYNAMIC_SBOX[ROUND_KEYS[i % 4] & 0xFF]];
    }
    memcpy(out, state, BLOCK_SIZE);
}

static void expand_key(const uint8_t *key_hash) {
    for (int i = 0; i < 8; i++) {
        ROUND_KEYS[i] = (key_hash[i*4] << 24) | (key_hash[i*4+1] << 16) | (key_hash[i*4+2] << 8) | key_hash[i*4+3];
    }
    for (int i = 8; i < ROUND_KEY_WORDS; i++) {
        uint32_t temp = ROUND_KEYS[i - 1];
        if (i % 8 == 0) {
            uint32_t rot = (temp << 8) | (temp >> 24);
            temp = (DYNAMIC_SBOX[(rot >> 24) & 0xFF] << 24) | (DYNAMIC_SBOX[(rot >> 16) & 0xFF] << 16) |
                   (DYNAMIC_SBOX[(rot >> 8) & 0xFF] << 8) | DYNAMIC_SBOX[rot & 0xFF];
            temp ^= K256[(i / 8) % 64];
        }
        ROUND_KEYS[i] = ROUND_KEYS[i - 8] ^ temp;
    }
}

/* --- Secure Key Derivation --- */
static void derive_keys(const char *pw, const uint8_t *salt, size_t salt_len, uint8_t enc_key[32], uint8_t mac_key[32]) {
    uint8_t master[64];
    pbkdf2_hmac_sha256(pw, strlen(pw), salt, salt_len, 100000, master, 64);
    memcpy(enc_key, master, 32);
    memcpy(mac_key, master + 32, 32);
    generate_key_dep_sbox(enc_key);
    expand_key(enc_key);
    ENGINE_READY = 1;
}

/* --- Stream Transform with Per-File Nonce --- */
static void transform(uint8_t *data, size_t len, const uint8_t nonce[BLOCK_SIZE]) {
    if (!ENGINE_READY) return;
    uint8_t counter[BLOCK_SIZE], keystream[BLOCK_SIZE];
    memcpy(counter, nonce, BLOCK_SIZE);
    size_t offset = 0;
    while (offset < len) {
        choi_encrypt_block(counter, keystream);
        size_t block = (len - offset) > BLOCK_SIZE ? BLOCK_SIZE : (len - offset);
        for (size_t i = 0; i < block; i++) data[offset + i] ^= keystream[i];
        offset += block;
        for (int i = BLOCK_SIZE - 1; i >= 0; i--) if (++counter[i]) break;
    }
}

/* --- CSPRNG Decoy (HMAC-DRBG style) --- */
static void generate_secure_decoy(const uint8_t *mac_key, size_t len, uint8_t *out) {
    uint8_t counter[32] = {0};
    uint8_t block[32];
    size_t offset = 0;
    while (offset < len) {
        hmac_sha256(mac_key, 32, counter, 32, block);
        size_t n = (len - offset < 32) ? (len - offset) : 32;
        memcpy(out + offset, block, n);
        offset += n;
        for (int i = 31; i >= 0; i--) if (++counter[i]) break;
    }
}

#endif
