#ifndef DYNAMIC_ASM_H
#define DYNAMIC_ASM_H

#include <stdint.h>
#include <stddef.h>

#define STATE_SIZE 16
#define NUM_ROUNDS 32

typedef enum {
    OP_XOR     = 0x00,
    OP_ARITH   = 0x01,
    OP_GALOIS  = 0x02,
    OP_NOT_MIX = 0x03
} asm_op_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Apply one round of dynamically selected operations to the state.
 *
 * The operation is selected by the 2 lowest bits of round_key[0].
 * All four operations are fully invertible given the same round key.
 */
void apply_dynamic_round(uint8_t state[STATE_SIZE],
                         const uint8_t round_key[STATE_SIZE]);

/**
 * @brief Reverse one round produced by apply_dynamic_round.
 */
void reverse_dynamic_round(uint8_t state[STATE_SIZE],
                           const uint8_t round_key[STATE_SIZE]);

/**
 * @brief Encrypt a 16-byte state with NUM_ROUNDS dynamic rounds.
 */
void dynamic_asm_encrypt(uint8_t state[STATE_SIZE],
                         uint8_t round_keys[NUM_ROUNDS][STATE_SIZE]);

/**
 * @brief Decrypt a 16-byte state encrypted by dynamic_asm_encrypt.
 */
void dynamic_asm_decrypt(uint8_t state[STATE_SIZE],
                         uint8_t round_keys[NUM_ROUNDS][STATE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* DYNAMIC_ASM_H */
