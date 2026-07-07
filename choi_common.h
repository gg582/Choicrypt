#ifndef CHOI_COMMON_H
#define CHOI_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================================================================
 * Choicrypt Common Header
 * ------------------------------------------------------------------
 * A custom experimental 128-bit block cipher built from standard
 * SP-network components (SubBytes, ShiftRows, MixColumns, AddRoundKey).
 * The S-box and part of the key schedule are key-dependent.
 *
 * WARNING: This is an experimental custom cipher. It has NOT undergone
 * peer review or wide cryptanalysis. Do not use for production or
 * regulated environments. Prefer AES-256-GCM or ChaCha20-Poly1305.
 * ================================================================== */

#define CHOI_BLOCK_SIZE   16
#define CHOI_KEY_SIZE     32
#define CHOI_SALT_SIZE    16
#define CHOI_NONCE_SIZE   16
#define CHOI_HMAC_SIZE    32
#define CHOI_NR           14
#define CHOI_ROUND_WORDS  (4 * (CHOI_NR + 1))

/* ------------------------------------------------------------------
 * SHA-256 Implementation (FIPS 180-4)
 * ------------------------------------------------------------------ */
#define CHOI_ROTR(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define CHOI_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define CHOI_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define CHOI_EP0(x)       (CHOI_ROTR(x, 2) ^ CHOI_ROTR(x, 13) ^ CHOI_ROTR(x, 22))
#define CHOI_EP1(x)       (CHOI_ROTR(x, 6) ^ CHOI_ROTR(x, 11) ^ CHOI_ROTR(x, 25))
#define CHOI_SIG0(x)      (CHOI_ROTR(x, 7) ^ CHOI_ROTR(x, 18) ^ ((x) >> 3))
#define CHOI_SIG1(x)      (CHOI_ROTR(x, 17) ^ CHOI_ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t choi_K256[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} choi_sha256_ctx;

static void choi_sha256_transform(choi_sha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    uint32_t i, j;
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for (; i < 64; ++i)
        m[i] = CHOI_SIG1(m[i - 2]) + m[i - 7] + CHOI_SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + CHOI_EP1(e) + CHOI_CH(e, f, g) + choi_K256[i] + m[i];
        t2 = CHOI_EP0(a) + CHOI_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void choi_sha256_init(choi_sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667U; ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U; ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU; ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU; ctx->state[7] = 0x5be0cd19U;
}

static void choi_sha256_update(choi_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            choi_sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512ULL;
            ctx->datalen = 0;
        }
    }
}

static void choi_sha256_final(choi_sha256_ctx *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        choi_sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8ULL;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    choi_sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xffU);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xffU);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xffU);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xffU);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xffU);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xffU);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xffU);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xffU);
    }
}

static void choi_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    choi_sha256_ctx ctx;
    choi_sha256_init(&ctx);
    choi_sha256_update(&ctx, data, len);
    choi_sha256_final(&ctx, hash);
}

static void choi_hmac_sha256(const uint8_t *key, size_t keylen,
                             const uint8_t *msg, size_t msglen,
                             uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    const uint8_t *k = key;
    size_t kl = keylen;

    if (keylen > 64) {
        choi_sha256(key, keylen, tk);
        k = tk; kl = 32;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < kl; ++i) {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }

    uint8_t inner[32];
    choi_sha256_ctx ctx;
    choi_sha256_init(&ctx);
    choi_sha256_update(&ctx, k_ipad, 64);
    choi_sha256_update(&ctx, msg, msglen);
    choi_sha256_final(&ctx, inner);

    choi_sha256_init(&ctx);
    choi_sha256_update(&ctx, k_opad, 64);
    choi_sha256_update(&ctx, inner, 32);
    choi_sha256_final(&ctx, out);
}

static void choi_pbkdf2_hmac_sha256(const char *pw, size_t pwlen,
                                    const uint8_t *salt, size_t saltlen,
                                    uint32_t iter,
                                    uint8_t *out, size_t outlen) {
    size_t i = 1;
    size_t generated = 0;
    uint8_t *salt_i = (uint8_t *)malloc(saltlen + 4);
    if (!salt_i) return;

    while (generated < outlen) {
        size_t need = (outlen - generated < 32) ? (outlen - generated) : 32;
        memcpy(salt_i, salt, saltlen);
        salt_i[saltlen]     = (uint8_t)((i >> 24) & 0xFF);
        salt_i[saltlen + 1] = (uint8_t)((i >> 16) & 0xFF);
        salt_i[saltlen + 2] = (uint8_t)((i >> 8) & 0xFF);
        salt_i[saltlen + 3] = (uint8_t)(i & 0xFF);

        uint8_t u[32], f[32];
        choi_hmac_sha256((const uint8_t*)pw, pwlen, salt_i, saltlen + 4, u);
        memcpy(f, u, 32);
        for (uint32_t c = 1; c < iter; ++c) {
            choi_hmac_sha256((const uint8_t*)pw, pwlen, u, 32, u);
            for (int j = 0; j < 32; ++j) f[j] ^= u[j];
        }
        memcpy(out + generated, f, need);
        generated += need;
        ++i;
    }
    free(salt_i);
}

/* ------------------------------------------------------------------
 * AES S-Box (source bijection)
 * ------------------------------------------------------------------ */
static const uint8_t CHOI_AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t CHOI_AES_INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* ------------------------------------------------------------------
 * Cipher Engine State
 * ------------------------------------------------------------------ */
static uint8_t  CHOI_SBOX[256];
static uint8_t  CHOI_INV_SBOX[256];
static uint32_t CHOI_ROUND_KEYS[CHOI_ROUND_WORDS];
static int      CHOI_ENGINE_READY = 0;

static void choi_generate_sbox(const uint8_t key_hash[32]) {
    memcpy(CHOI_SBOX, CHOI_AES_SBOX, 256);
    /* Fisher-Yates shuffle seeded by key_hash using a simple PRNG.
     * The result is a permutation (bijection) because we only swap. */
    uint32_t state = ((uint32_t)key_hash[0] << 24) |
                     ((uint32_t)key_hash[1] << 16) |
                     ((uint32_t)key_hash[2] << 8)  |
                     (uint32_t)key_hash[3];
    if (state == 0) state = 0x12345678U;
    for (int i = 255; i > 0; --i) {
        state = state * 1664525U + 1013904223U;
        uint32_t j = (state ^ key_hash[i % 32]) % (uint32_t)(i + 1);
        uint8_t tmp = CHOI_SBOX[i];
        CHOI_SBOX[i] = CHOI_SBOX[j];
        CHOI_SBOX[j] = tmp;
    }
    /* Build inverse table and verify bijection. */
    int ok = 1;
    memset(CHOI_INV_SBOX, 0, 256);
    for (int i = 0; i < 256; ++i) {
        CHOI_INV_SBOX[CHOI_SBOX[i]] = (uint8_t)i;
    }
    for (int i = 0; i < 256; ++i) {
        if (CHOI_SBOX[CHOI_INV_SBOX[i]] != (uint8_t)i) ok = 0;
    }
    if (!ok) {
        /* Fallback should never happen, but keep engine deterministic. */
        memcpy(CHOI_SBOX, CHOI_AES_SBOX, 256);
        memcpy(CHOI_INV_SBOX, CHOI_AES_INV_SBOX, 256);
    }
}

/* ------------------------------------------------------------------
 * SP-network Primitives
 * ------------------------------------------------------------------ */
static inline void choi_sub_bytes(uint8_t state[CHOI_BLOCK_SIZE]) {
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i) state[i] = CHOI_SBOX[state[i]];
}

static inline void choi_inv_sub_bytes(uint8_t state[CHOI_BLOCK_SIZE]) {
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i) state[i] = CHOI_INV_SBOX[state[i]];
}

static inline void choi_shift_rows(uint8_t state[CHOI_BLOCK_SIZE]) {
    /* AES shift rows on 4x4 byte matrix (row-major). */
    uint8_t t;
    /* row 1: shift left by 1 */
    t = state[4];  state[4]  = state[5];  state[5]  = state[6];  state[6]  = state[7];  state[7]  = t;
    /* row 2: shift left by 2 */
    t = state[8];  state[8]  = state[10]; state[10] = t;
    t = state[9];  state[9]  = state[11]; state[11] = t;
    /* row 3: shift left by 3 (or right by 1) */
    t = state[15]; state[15] = state[14]; state[14] = state[13]; state[13] = state[12]; state[12] = t;
}

static inline void choi_inv_shift_rows(uint8_t state[CHOI_BLOCK_SIZE]) {
    uint8_t t;
    /* row 1: shift right by 1 */
    t = state[7];  state[7]  = state[6];  state[6]  = state[5];  state[5]  = state[4];  state[4]  = t;
    /* row 2: shift right by 2 */
    t = state[8];  state[8]  = state[10]; state[10] = t;
    t = state[9];  state[9]  = state[11]; state[11] = t;
    /* row 3: shift right by 3 (or left by 1) */
    t = state[12]; state[12] = state[13]; state[13] = state[14]; state[14] = state[15]; state[15] = t;
}

static inline uint8_t choi_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80U) ? 0x1bU : 0x00U));
}

static inline uint8_t choi_gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1U) p ^= a;
        uint8_t hi = a & 0x80U;
        a <<= 1;
        if (hi) a ^= 0x1bU;
        b >>= 1;
    }
    return p;
}

static void choi_mix_columns(uint8_t state[CHOI_BLOCK_SIZE]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t *col = state + c * 4;
        uint8_t s0 = col[0], s1 = col[1], s2 = col[2], s3 = col[3];
        col[0] = choi_xtime(s0) ^ (s1 ^ choi_xtime(s1)) ^ s2 ^ s3;
        col[1] = s0 ^ choi_xtime(s1) ^ (s2 ^ choi_xtime(s2)) ^ s3;
        col[2] = s0 ^ s1 ^ choi_xtime(s2) ^ (s3 ^ choi_xtime(s3));
        col[3] = (s0 ^ choi_xtime(s0)) ^ s1 ^ s2 ^ choi_xtime(s3);
    }
}

static void choi_inv_mix_columns(uint8_t state[CHOI_BLOCK_SIZE]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t *col = state + c * 4;
        uint8_t s0 = col[0], s1 = col[1], s2 = col[2], s3 = col[3];
        col[0] = choi_gf_mul(s0, 0x0e) ^ choi_gf_mul(s1, 0x0b) ^ choi_gf_mul(s2, 0x0d) ^ choi_gf_mul(s3, 0x09);
        col[1] = choi_gf_mul(s0, 0x09) ^ choi_gf_mul(s1, 0x0e) ^ choi_gf_mul(s2, 0x0b) ^ choi_gf_mul(s3, 0x0d);
        col[2] = choi_gf_mul(s0, 0x0d) ^ choi_gf_mul(s1, 0x09) ^ choi_gf_mul(s2, 0x0e) ^ choi_gf_mul(s3, 0x0b);
        col[3] = choi_gf_mul(s0, 0x0b) ^ choi_gf_mul(s1, 0x0d) ^ choi_gf_mul(s2, 0x09) ^ choi_gf_mul(s3, 0x0e);
    }
}

/* ------------------------------------------------------------------
 * Hexagonal Layer
 * ------------------------------------------------------------------
 * The 16-byte state is viewed as 16 nodes arranged in a hexagonal
 * ring.  Node i is paired with its antipode (i + 8) % 16.  The layer
 * applies a key-dependent non-linear shuffle through the S-box while
 * remaining fully invertible.
 * ------------------------------------------------------------------ */
static inline void choi_hexagonal_layer(uint8_t state[CHOI_BLOCK_SIZE], int round) {
    const uint8_t *rk = (const uint8_t *)&CHOI_ROUND_KEYS[round * 4];
    uint8_t tmp[CHOI_BLOCK_SIZE];
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i) {
        tmp[i] = CHOI_SBOX[state[(i + 8) % CHOI_BLOCK_SIZE] ^ rk[i]];
    }
    memcpy(state, tmp, CHOI_BLOCK_SIZE);
}

static inline void choi_inv_hexagonal_layer(uint8_t state[CHOI_BLOCK_SIZE], int round) {
    const uint8_t *rk = (const uint8_t *)&CHOI_ROUND_KEYS[round * 4];
    uint8_t tmp[CHOI_BLOCK_SIZE];
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i) {
        tmp[(i + 8) % CHOI_BLOCK_SIZE] = CHOI_INV_SBOX[state[i]] ^ rk[i];
    }
    memcpy(state, tmp, CHOI_BLOCK_SIZE);
}

static inline void choi_add_round_key(uint8_t state[CHOI_BLOCK_SIZE], int round) {
    const uint8_t *rk = (const uint8_t *)&CHOI_ROUND_KEYS[round * 4];
    for (int i = 0; i < CHOI_BLOCK_SIZE; ++i) state[i] ^= rk[i];
}

/* ------------------------------------------------------------------
 * Key Schedule (AES-256 style with dynamic S-Box)
 * ------------------------------------------------------------------ */
static const uint8_t CHOI_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static inline uint32_t choi_rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

static inline uint32_t choi_sub_word(uint32_t w) {
    return ((uint32_t)CHOI_SBOX[(w >> 24) & 0xff] << 24) |
           ((uint32_t)CHOI_SBOX[(w >> 16) & 0xff] << 16) |
           ((uint32_t)CHOI_SBOX[(w >> 8)  & 0xff] << 8)  |
           ((uint32_t)CHOI_SBOX[w & 0xff]);
}

static void choi_expand_key(const uint8_t master_key[CHOI_KEY_SIZE]) {
    /* Load first 8 words from master key. */
    for (int i = 0; i < 8; ++i) {
        CHOI_ROUND_KEYS[i] = ((uint32_t)master_key[i * 4]     << 24) |
                             ((uint32_t)master_key[i * 4 + 1] << 16) |
                             ((uint32_t)master_key[i * 4 + 2] << 8)  |
                             ((uint32_t)master_key[i * 4 + 3]);
    }

    for (int i = 8; i < CHOI_ROUND_WORDS; ++i) {
        uint32_t temp = CHOI_ROUND_KEYS[i - 1];
        if (i % 8 == 0) {
            temp = choi_sub_word(choi_rot_word(temp)) ^
                   ((uint32_t)CHOI_RCON[i / 8] << 24);
        } else if (i % 8 == 4) {
            temp = choi_sub_word(temp);
        }
        CHOI_ROUND_KEYS[i] = CHOI_ROUND_KEYS[i - 8] ^ temp;
    }
}

/* ------------------------------------------------------------------
 * Block Encryption / Decryption
 * ------------------------------------------------------------------ */
static void choi_encrypt_block(const uint8_t in[CHOI_BLOCK_SIZE],
                               uint8_t out[CHOI_BLOCK_SIZE]) {
    uint8_t state[CHOI_BLOCK_SIZE];
    memcpy(state, in, CHOI_BLOCK_SIZE);

    choi_add_round_key(state, 0);
    for (int round = 1; round < CHOI_NR; ++round) {
        choi_sub_bytes(state);
        choi_shift_rows(state);
        choi_mix_columns(state);
        choi_hexagonal_layer(state, round);
        choi_add_round_key(state, round);
    }
    choi_sub_bytes(state);
    choi_shift_rows(state);
    choi_hexagonal_layer(state, CHOI_NR);
    choi_add_round_key(state, CHOI_NR);

    memcpy(out, state, CHOI_BLOCK_SIZE);
}

static void choi_decrypt_block(const uint8_t in[CHOI_BLOCK_SIZE],
                               uint8_t out[CHOI_BLOCK_SIZE]) {
    uint8_t state[CHOI_BLOCK_SIZE];
    memcpy(state, in, CHOI_BLOCK_SIZE);

    choi_add_round_key(state, CHOI_NR);
    choi_inv_hexagonal_layer(state, CHOI_NR);
    choi_inv_shift_rows(state);
    choi_inv_sub_bytes(state);
    for (int round = CHOI_NR - 1; round >= 1; --round) {
        choi_add_round_key(state, round);
        choi_inv_hexagonal_layer(state, round);
        choi_inv_mix_columns(state);
        choi_inv_shift_rows(state);
        choi_inv_sub_bytes(state);
    }
    choi_add_round_key(state, 0);

    memcpy(out, state, CHOI_BLOCK_SIZE);
}

/* ------------------------------------------------------------------
 * Key Derivation
 * ------------------------------------------------------------------ */
static void choi_derive_keys(const char *pw,
                             const uint8_t salt[CHOI_SALT_SIZE],
                             uint8_t enc_key[CHOI_KEY_SIZE],
                             uint8_t mac_key[CHOI_KEY_SIZE]) {
    uint8_t master[CHOI_KEY_SIZE * 2];
    choi_pbkdf2_hmac_sha256(pw, strlen(pw), salt, CHOI_SALT_SIZE, 100000,
                            master, sizeof(master));
    memcpy(enc_key, master, CHOI_KEY_SIZE);
    memcpy(mac_key, master + CHOI_KEY_SIZE, CHOI_KEY_SIZE);

    /* Initialize the cipher engine from the encryption key. */
    uint8_t key_hash[32];
    choi_sha256(enc_key, CHOI_KEY_SIZE, key_hash);
    choi_generate_sbox(key_hash);
    choi_expand_key(enc_key);
    CHOI_ENGINE_READY = 1;

    /* Clean intermediate material. */
    memset(master, 0, sizeof(master));
    memset(key_hash, 0, sizeof(key_hash));
}

/* ------------------------------------------------------------------
 * CTR Mode Stream Transform
 * ------------------------------------------------------------------ */
static void choi_transform(uint8_t *data, size_t len,
                           const uint8_t nonce[CHOI_NONCE_SIZE]) {
    if (!CHOI_ENGINE_READY) return;

    uint8_t counter[CHOI_BLOCK_SIZE];
    uint8_t keystream[CHOI_BLOCK_SIZE];
    memcpy(counter, nonce, CHOI_NONCE_SIZE);
    memset(counter + CHOI_NONCE_SIZE, 0, CHOI_BLOCK_SIZE - CHOI_NONCE_SIZE);

    size_t offset = 0;
    while (offset < len) {
        choi_encrypt_block(counter, keystream);
        size_t block = (len - offset > CHOI_BLOCK_SIZE) ? CHOI_BLOCK_SIZE : (len - offset);
        for (size_t i = 0; i < block; ++i) data[offset + i] ^= keystream[i];
        offset += block;
        /* Increment counter as a big-endian 128-bit integer. */
        for (int i = CHOI_BLOCK_SIZE - 1; i >= 0; --i) {
            if (++counter[i]) break;
        }
    }
}

/* ------------------------------------------------------------------
 * Decoy Generation (experimental, NOT full Honey Encryption)
 * ------------------------------------------------------------------ */
static void choi_generate_decoy(const uint8_t *ct, size_t ct_len,
                                uint8_t *out, size_t out_len) {
    /* Deterministic decoy for a given ciphertext, independent of the
     * guessed key. Uses a fixed all-zero HMAC key so every wrong key
     * produces the same decoy for the same ciphertext. */
    static const uint8_t zero_key[CHOI_HMAC_SIZE] = {0};
    uint8_t seed[CHOI_HMAC_SIZE];
    choi_hmac_sha256(zero_key, CHOI_HMAC_SIZE, ct, ct_len, seed);

    uint8_t counter[CHOI_HMAC_SIZE] = {0};
    size_t offset = 0;
    while (offset < out_len) {
        uint8_t block[CHOI_HMAC_SIZE];
        choi_hmac_sha256(seed, CHOI_HMAC_SIZE, counter, CHOI_HMAC_SIZE, block);
        size_t n = (out_len - offset < CHOI_HMAC_SIZE) ? (out_len - offset) : CHOI_HMAC_SIZE;
        memcpy(out + offset, block, n);
        offset += n;
        for (int i = CHOI_HMAC_SIZE - 1; i >= 0; --i) {
            if (++counter[i]) break;
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif /* CHOI_COMMON_H */
