/*
 * obfuscated_pipeline.h — Reversible obfuscation pipeline
 *
 * Provides a control-flow-flattened, P-Box + bytecode based pipeline
 * that is fully invertible.  This is an experimental module for
 * studying obfuscation techniques, not a replacement for authenticated
 * encryption.
 */

#ifndef OBFUSCATED_PIPELINE_H
#define OBFUSCATED_PIPELINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OBF_MAX_ROUNDS 64
#define OBF_STATE_SIZE 16

/**
 * @brief Generate all round keys for the pipeline from a 32-byte seed.
 *
 * The first round key is derived from the seed; subsequent keys use a
 * rolling-key feedback rule that depends on the state produced during
 * encryption.  Therefore this function only produces round_key[0];
 * the caller must run obf_pipeline_encrypt() to obtain the full array.
 */
void obf_init_round_keys(const uint8_t seed[32],
                         int num_rounds,
                         uint8_t round_keys[OBF_MAX_ROUNDS][OBF_STATE_SIZE]);

/**
 * @brief Encrypt/obfuscate a 16-byte state.
 *
 * @param state        16-byte state, modified in place.
 * @param seed         32-byte seed.
 * @param num_rounds   Number of rounds (<= OBF_MAX_ROUNDS).
 * @param round_keys   Output: all generated round keys.  Must be supplied
 *                     unchanged to obf_pipeline_decrypt().
 */
void obf_pipeline_encrypt(uint8_t state[OBF_STATE_SIZE],
                          const uint8_t seed[32],
                          int num_rounds,
                          uint8_t round_keys[OBF_MAX_ROUNDS][OBF_STATE_SIZE]);

/**
 * @brief Decrypt/deobfuscate a 16-byte state.
 *
 * @param state        16-byte obfuscated state, modified in place.
 * @param seed         Same 32-byte seed used for encryption.
 * @param num_rounds   Same number of rounds used for encryption.
 * @param round_keys   Round keys produced by obf_pipeline_encrypt().
 */
void obf_pipeline_decrypt(uint8_t state[OBF_STATE_SIZE],
                          const uint8_t seed[32],
                          int num_rounds,
                          const uint8_t round_keys[OBF_MAX_ROUNDS][OBF_STATE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* OBFUSCATED_PIPELINE_H */
