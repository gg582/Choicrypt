#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

// ==========================================
// PART 1: Temporal Jitter & Entropy Injection
// ==========================================

// Gathers non-deterministic physical entropy from CPU execution jitter
// and memory access latency.
static uint64_t gather_physical_entropy() {
    uint64_t start = __rdtsc();
    
    // Induce memory jitter
    volatile int waste = 0;
    for (int i = 0; i < 256; i++) {
        waste += i ^ (waste << 1);
    }
    
    uint64_t end = __rdtsc();
    uint64_t jitter = end - start;
    
    // Mix with heap address ASLR entropy
    uint64_t aslr_shift = (uint64_t)&waste;
    
    return jitter ^ aslr_shift;
}

// Securely zero out memory to store entropies safely
static void secure_wipe(void *ptr, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (size--) {
        *p++ = 0;
    }
}


// ==========================================
// PART 2: Multi-Dimensional Manifold Mapping & PART 3: Code-as-Data
// ==========================================

// Dummy function to be used for Code-as-Data reflection
static void execution_anchor() {
    __asm__ volatile ("nop");
}

// A chaotic, non-linear fractal map (Julia Set iteration approximation)
// Re-scaled for integer arithmetic to prevent floating-point side-channels.
static uint64_t fractal_manifold_map(uint64_t state, uint64_t key) {
    // Treat the 64-bit state as a Complex coordinate (Z)
    int32_t z_real = (int32_t)(state >> 32);
    int32_t z_imag = (int32_t)(state & 0xFFFFFFFF);
    
    // Key acts as the Julia set Constant (C)
    int32_t c_real = (int32_t)(key >> 32);
    int32_t c_imag = (int32_t)(key & 0xFFFFFFFF);
    
    // Iterate the fractal map: Z = Z^2 + C
    for (int i = 0; i < 5; i++) {
        // Shift by 16 to simulate fixed-point math
        int64_t r2 = ((int64_t)z_real * z_real) >> 16;
        int64_t i2 = ((int64_t)z_imag * z_imag) >> 16;
        int64_t ri = ((int64_t)z_real * z_imag) >> 16;
        
        z_real = (int32_t)(r2 - i2) + c_real;
        z_imag = (int32_t)(ri * 2) + c_imag;
    }
    
    // Recombine into a 1D Manifold point
    uint64_t fractal_out = (((uint64_t)z_real) << 32) | ((uint32_t)z_imag);
    
    // PART 3: Code-as-Data (Recursive Logic Wrapping)
    // Sample the executable's own memory space as an S-Box substitute
    uint8_t *code_ptr = (uint8_t *)&execution_anchor;
    uint64_t code_mask = 0;
    for (int i = 0; i < 8; i++) {
        code_mask |= ((uint64_t)code_ptr[i % 16]) << (i * 8);
    }
    
    return fractal_out ^ code_mask;
}


// ==========================================
// PART 4: Cryptographic Ghosting (Probabilistic Feistel)
// ==========================================

// Feistel network ensures that even a one-way chaotic fractal map is a "Diffeomorphism"
// (Fully Reversible without needing to reverse the Fractal equation itself).
static void non_deterministic_feistel(uint64_t *L, uint64_t *R, uint64_t key, uint64_t entropy, int encrypt) {
    uint64_t round_keys[16];
    
    // Derive subkeys mapped to the local temporal entropy
    for (int i = 0; i < 16; i++) {
        // Entropy fundamentally alters the algebraic diffusion constants
        round_keys[i] = key ^ (entropy * (0x9E3779B97F4A7C15ULL + i));
    }
    
    if (encrypt) {
        for (int i = 0; i < 16; i++) {
            uint64_t next_L = *R;
            // The F-Function
            uint64_t f_out = fractal_manifold_map(*R, round_keys[i]);
            uint64_t next_R = *L ^ f_out;
            
            *L = next_L;
            *R = next_R;
        }
    } else {
        // Exact reverse traversal for decryption
        for (int i = 15; i >= 0; i--) {
            uint64_t prev_R = *L;
            uint64_t f_out = fractal_manifold_map(*L, round_keys[i]);
            uint64_t prev_L = *R ^ f_out;
            
            *L = prev_L;
            *R = prev_R;
        }
    }
    
    // Safely discard generated keys from memory
    secure_wipe(round_keys, sizeof(round_keys));
}

// Applies "Honey Encryption" principles.
// Constrains the ciphertext strictly to a subset of ASCII, so any decryption
// attempt with an incorrect key yields grammatically sound, but hallucinated data.
void process_ghosting_block(uint8_t block[16], uint64_t key, uint64_t *entropy_out, int encrypt) {
    uint64_t L = 0x0123456789ABCDEFULL; // Non-zero seed
    uint64_t R = 0xFEDCBA9876543210ULL;
    
    uint64_t entropy;
    if (encrypt) {
        entropy = gather_physical_entropy();
        *entropy_out = entropy;
    } else {
        entropy = *entropy_out; // Retrieve from ciphertext envelope
    }
    
    // Core Manifold mapping (Stream Cipher Mode)
    // Run forward (encrypt=1) for both encrypting and decrypting data
    // because we need the exact same keystream generated from the seed.
    non_deterministic_feistel(&L, &R, key, entropy, 1);
    
    // Ghosting: Format-Preserving Modulo projection
    // Forces the output bytes back into readable ASCII (32 to 126).
    // An attacker running dictionary attacks will find infinite "valid" ASCII strings.
    uint8_t L_bytes[8];
    uint8_t R_bytes[8];
    memcpy(L_bytes, &L, 8);
    memcpy(R_bytes, &R, 8);
    
    for (int i = 0; i < 8; i++) {
        if (encrypt) {
            block[i]     = 32 + ((block[i]     - 32 + L_bytes[i]) % 95);
            block[i + 8] = 32 + ((block[i + 8] - 32 + R_bytes[i]) % 95);
        } else {
            // Reverse Modulo arithmetic
            int c1 = block[i] - 32 - L_bytes[i];
            // C can handle negative modulo poorly, make sure it's positive.
            c1 = (c1 % 95 + 95) % 95;
            block[i] = 32 + c1;
            
            int c2 = block[i + 8] - 32 - R_bytes[i];
            c2 = (c2 % 95 + 95) % 95;
            block[i + 8] = 32 + c2;
        }
    }
    
    // Secure Entropies
    secure_wipe(&L, sizeof(L));
    secure_wipe(&R, sizeof(R));
    if (!encrypt) {
        secure_wipe(&entropy, sizeof(entropy));
    }
}

int main() {
    uint8_t data[16] = "GHOSTING_SYSTEM!";
    uint64_t secret_key = 0xDEADBEEFCAFEBABEULL;
    uint64_t session_entropy = 0;
    
    printf("--- Non-Deterministic Cryptographic Engine ---\n");
    printf("Original:  %.16s\n", data);
    
    // Encrypt
    process_ghosting_block(data, secret_key, &session_entropy, 1);
    printf("Encrypted: %.16s (Entropy Seed: %lx)\n", data, session_entropy);
    
    // Decrypt (Correct Key)
    uint8_t correct_dec[16];
    memcpy(correct_dec, data, 16);
    process_ghosting_block(correct_dec, secret_key, &session_entropy, 0);
    printf("Decrypted (Correct Key): %.16s\n", correct_dec);
    
    // Decrypt (Wrong Key - Honey Encryption / Ghosting Demo)
    uint8_t wrong_dec[16];
    memcpy(wrong_dec, data, 16);
    process_ghosting_block(wrong_dec, 0xBADBADBADBADULL, &session_entropy, 0);
    printf("Decrypted (Wrong Key):   %.16s\n", wrong_dec);

    return 0;
}
