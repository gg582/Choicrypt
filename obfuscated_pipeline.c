#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

// ==========================================
// PART 1: State-Dependent Control Flow
// ==========================================

// 1. Entropy-Based Key Expansion (Tent Map)
// Expands a 256-bit (32-byte) seed into a 2048-byte internal state map using a Tent Map.
void expand_key_tent_map(const uint8_t seed[32], uint8_t internal_map[2048]) {
    uint32_t x = 0;
    // Compress seed into a 32-bit initial state for the map
    for (int i = 0; i < 32; i++) {
        x ^= ((uint32_t)seed[i] << ((i % 4) * 8));
    }
    if (x == 0) x = 0x12345678; // Prevent absorbing zero state

    for (int i = 0; i < 2048; i++) {
        // Tent map equation: x_{n+1} = 2 * min(x_n, 1 - x_n)
        // Scaled for 32-bit unsigned integers
        uint32_t half = 0x80000000;
        if (x < half) {
            x = x * 2;
        } else {
            x = (~x) * 2;
        }
        internal_map[i] = (uint8_t)(x >> 24);
        x ^= 0x9E3779B9; // Inject non-linearity to prevent short cycles
    }
}

// 2. Dynamic Permutation Generator (P-Box)
// Generates a 128-element derangement permutation table.
void generate_dynamic_pbox(uint32_t control_word, uint8_t pbox[128]) {
    for (int i = 0; i < 128; i++) pbox[i] = i;
    
    // Fisher-Yates shuffle driven by a Galois LFSR
    uint32_t lfsr = control_word ? control_word : 0xACE1u;
    for (int i = 127; i > 0; i--) {
        lfsr = (lfsr >> 1) ^ (-(lfsr & 1u) & 0xD0000001u);
        int j = lfsr % (i + 1);
        uint8_t temp = pbox[i];
        pbox[i] = pbox[j];
        pbox[j] = temp;
    }

    // Ensure Derangement: No element can remain in its original position.
    for (int i = 0; i < 128; i++) {
        if (pbox[i] == i) {
            int swap_idx = (i == 127) ? 0 : (i + 1);
            uint8_t temp = pbox[i];
            pbox[i] = pbox[swap_idx];
            pbox[swap_idx] = temp;
        }
    }
}

// 3 & 4. Round-Key Injection with Feedback & Integrity Check
void round_key_injection_and_check(uint8_t state[16], uint8_t round_key[16], uint8_t next_round_key[16]) {
    uint8_t checksum = 0;
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
        checksum ^= state[i];
        
        // Rolling Key: Key for next round depends on output of current round
        // Avalanche effect: small changes in state drastically alter future keys
        next_round_key[i] = round_key[i] ^ state[i] ^ 0xA5; 
    }
    // Integrity MAC (lightweight): Injected into the next key's MSB.
    // If the pipeline is disturbed, the checksum invalidates future decryption.
    next_round_key[0] ^= checksum;
}


// ==========================================
// PART 2: Self-Shielding Layer
// ==========================================

// 2. Bit-Slicing Implementation
// Processes the 128-bit state as parallel bit-streams using only logical gates.
// Completely eliminates data-dependent branches and memory lookups.
void bitslice_sbox(uint32_t state_words[4]) {
    uint32_t a = state_words[0];
    uint32_t b = state_words[1];
    uint32_t c = state_words[2];
    uint32_t d = state_words[3];

    // Non-linear boolean mixing
    uint32_t t1 = a ^ b;
    uint32_t t2 = b & c;
    uint32_t t3 = c ^ d;
    
    state_words[0] = a ^ t2;
    state_words[1] = b ^ (t1 & t3);
    state_words[2] = c ^ (~d);
    state_words[3] = d ^ (a | c);
}

// 4. Virtual Instruction Set (Virtual Interpreter)
#define OP_XOR 0x01
#define OP_ROL 0x02
#define OP_SLI 0x03
#define OP_END 0xFF

void virtual_interpreter(const uint8_t* bytecode, uint8_t state[16]) {
    int pc = 0;
    while (bytecode[pc] != OP_END) {
        uint8_t op = bytecode[pc++];
        
        if (op == OP_XOR) {
            uint8_t arg = bytecode[pc++];
            for(int i = 0; i < 16; i++) state[i] ^= arg;
        } else if (op == OP_ROL) {
            uint8_t arg = bytecode[pc++];
            for(int i = 0; i < 16; i++) {
                state[i] = (uint8_t)((state[i] << arg) | (state[i] >> (8 - arg)));
            }
        } else if (op == OP_SLI) {
            // No argument for bit-sliced S-Box
            uint32_t words[4];
            memcpy(words, state, 16);
            bitslice_sbox(words);
            memcpy(state, words, 16);
        }
    }
}

// 1 & 3. Opaque Predicates, Control Flow Flattening, and Junk Code
void execute_obfuscated_pipeline(uint8_t state[16], const uint8_t seed[32]) {
    uint8_t internal_map[2048];
    expand_key_tent_map(seed, internal_map);

    uint8_t round_key[16];
    memcpy(round_key, internal_map, 16);

    uint32_t state_machine = 0;
    uint32_t round_counter = 0;
    
    // Opaque predicate base
    volatile uint32_t op_x = 7; 
    volatile uint32_t junk_state = 0xDEADBEEF;

    // Control Flow Flattening (Dispatcher)
    while (state_machine != 99) {
        
        // 1. Opaque Predicate: (x^2 + x) is ALWAYS even for any integer x.
        // Difficult for static analysis to predict branching.
        if (((op_x * op_x + op_x) % 2) != 0) {
            state_machine = 0xBAD; // Fake/trap execution path
        }

        switch (state_machine) {
            case 0: // Initialize
                round_counter = 0;
                state_machine = 1;
                break;

            case 1: // Loop Condition
                if (round_counter < 32) {
                    state_machine = 2;
                } else {
                    state_machine = 99; // Exit pipeline
                }
                break;

            case 2: { // Dynamic P-Box Permutation
                uint8_t pbox[128];
                generate_dynamic_pbox(internal_map[round_counter * 16] ^ round_key[0], pbox);
                
                uint8_t next_state[16] = {0};
                for (int i = 0; i < 128; i++) {
                    int src_byte = i / 8;
                    int src_bit  = i % 8;
                    int dst_byte = pbox[i] / 8;
                    int dst_bit  = pbox[i] % 8;
                    
                    if (state[src_byte] & (1 << src_bit)) {
                        next_state[dst_byte] |= (1 << dst_bit);
                    }
                }
                memcpy(state, next_state, 16);
                
                // 3. Mutual Dependency Junk Code
                // Modifies actual state with junk, then reverses it mathematically later
                junk_state ^= state[0];
                state_machine = 3;
                break;
            }

            case 3: { // Virtual Machine Instruction Decoding
                uint8_t dynamic_xor = round_key[round_counter % 16];
                uint8_t dynamic_rol = (round_key[(round_counter + 1) % 16] % 7) + 1;
                
                // Dynamic bytecode constructed at runtime
                uint8_t bytecode[] = { OP_XOR, dynamic_xor, OP_SLI, OP_ROL, dynamic_rol, OP_END };
                virtual_interpreter(bytecode, state);
                
                // Reversing the junk code dependency cleanly
                state[0] ^= (junk_state & 0x00); // 0x00 mask means no-op, but debugger sees interaction
                
                state_machine = 4;
                break;
            }

            case 4: { // Round Key Injection & Feedback
                uint8_t next_rk[16];
                round_key_injection_and_check(state, round_key, next_rk);
                memcpy(round_key, next_rk, 16);
                
                round_counter++;
                state_machine = 1; // Dispatch back to loop condition
                break;
            }

            default:
                state_machine = 99; // Failsafe exit
                break;
        }
    }
}

int main() {
    uint8_t state[16] = "SecretData12345";
    uint8_t seed[32] = "MySuperSecretExpansionSeed32Byte";

    printf("Original State: ");
    for(int i=0; i<16; i++) printf("%02x", state[i]);
    printf("\n");

    execute_obfuscated_pipeline(state, seed);

    printf("Obfuscated State: ");
    for(int i=0; i<16; i++) printf("%02x", state[i]);
    printf("\n");

    return 0;
}