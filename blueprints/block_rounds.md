# Jisugwimundo Block Cipher Round Logic (32 Rounds)

```mermaid
graph TD
    subgraph Initialization
        Input[128-bit Plaintext Block] --> State[16-byte State Vector]
    end

    subgraph Round_0
        State --> ARK0[AddRoundKey 0 (S-Box Masked)]
    end

    subgraph Intermediate_Rounds_1_to_31
        ARK0 --> SB[Key-Dependent SubBytes]
        SB --> SR[ShiftRows]
        SR --> HR[Hexagonal Refraction (Fractal Chaos)]
        HR --> ARK[AddRoundKey N (S-Box Masked)]
    end

    subgraph Final_Round_32
        ARK --> SB32[Key-Dependent SubBytes]
        SB32 --> SR32[ShiftRows]
        SR32 --> ARK32[AddRoundKey 32 (S-Box Masked)]
        ARK32 --> FCL[Final Chaos Layer (S-Box / Key Ripple)]
    end

    subgraph Output
        FCL --> Out[128-bit Ciphertext Block]
    end

    %% Loop for Rounds 1-31
    ARK -- "Repeated for Rounds 1-31" --> SB
```

### Hexagonal Refraction (Inner Loop: 32 iterations)
1. **Geometric Mapping:** Map state to 16 nodes of a Jisugwimundo-inspired hexagonal mesh.
2. **Fractal Chaos:** Each node undergoes 6 iterations of the fractal map $Z = Z^2 + C$, where $C$ is derived from the Round Key and $Z$ is the sum of adjacent nodes.
3. **Horizontal Diffusion:** A ripple effect across all 16 nodes to break local relationships.
4. **Key Injection:** Round Key is injected through the Dynamic S-Box to ensure maximum non-linearity.
