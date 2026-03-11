#ifndef DYNAMIC_ASM_H
#define DYNAMIC_ASM_H

#include <stdint.h>
#include <stddef.h>

#define STATE_SIZE 16
#define NUM_ROUNDS 32

/**
 * @brief Initialize the cipher engine with a password.
 * 
 * @param pw The password string.
 */
void dynamic_asm_init(const char *pw);

/**
 * @brief Full encryption process using 32 rounds of dynamic state machine.
 */
void dynamic_asm_encrypt(uint8_t state[STATE_SIZE]);

/**
 * @brief Full decryption process using 32 rounds of dynamic state machine.
 */
void dynamic_asm_decrypt(uint8_t state[STATE_SIZE]);

#endif // DYNAMIC_ASM_H
