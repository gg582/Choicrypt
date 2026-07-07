# Choicrypt

Choicrypt is an **experimental, educational 128-bit block cipher** that
preserves a custom design identity while adopting the structural
discipline of standard SP-networks (Substitution–Permutation networks).
It is intended for learning, CTF challenges, and obfuscation research,
**not** for production or regulated environments.

> ⚠️ **Security Notice**
> Choicrypt is a custom (non-standard) cipher. It has not undergone peer
> review, wide cryptanalysis, or formal certification. For sensitive data,
> regulated systems, or any scenario where real security is required, use
> established primitives such as **AES-256-GCM** or **ChaCha20-Poly1305**.

---

## 1. Design Overview

| Parameter | Value |
|-----------|-------|
| Block size | 128 bits (16 bytes) |
| Key size | 256 bits (derived from password) |
| Rounds | 14 |
| Mode of operation | CTR (counter mode) |
| Authentication | HMAC-SHA256 |
| Key derivation | PBKDF2-HMAC-SHA256, 100,000 iterations |
| Salt / Nonce | 16 bytes each, randomly generated per file |

### 1.1 Round Function

Each round applies five invertible layers:

```
SubBytes         -> key-dependent dynamic S-Box (bijection)
ShiftRows        -> byte rotation across the 4x4 state
MixColumns       -> GF(2⁸) matrix multiplication (AES irreducible polynomial 0x11B)
HexagonalLayer   -> key-dependent antipodal S-Box shuffle on a 16-node ring
AddRoundKey      -> XOR with the round key
```

The 16-byte state is viewed as 16 nodes on a hexagonal ring; node `i` is
paired with its antipode `(i + 8) % 16`.  `HexagonalLayer` reads from the
antipode, XORs with the round key, and passes the result through the dynamic
S-Box.  This operation is fully invertible (the inverse reads back through
the antipode and applies `InvS-Box`), and provides an additional non-linear
diffusion step inspired by the geometry of the hexagonal lattice.

The final round omits `MixColumns`, matching AES convention, but keeps the
`HexagonalLayer` so the key-dependent antipodal shuffle is present in every
round.

### 1.2 SIMD Acceleration

On x86-64 targets the build enables `-mssse3` and the SP-network uses
SSSE3 intrinsics for the linear layers:

* `AddRoundKey` — 128-bit XOR (`_mm_xor_si128`)
* `ShiftRows` / `InvShiftRows` — byte shuffle (`_mm_shuffle_epi8`)
* `MixColumns` / `InvMixColumns` — 4-column parallel GF(2⁸) arithmetic

The key-dependent S-Box and the `HexagonalLayer` remain scalar because their
256-entry lookups do not vectorise cleanly without AVX-512 VBMI2 or large
bit-matrix tricks.  If SSSE3 is unavailable at compile time the code falls
back to the scalar implementations.

### 1.3 Key-Dependent S-Box

The dynamic S-Box starts from the AES S-Box and is shuffled with a
Fisher–Yates permutation seeded by `SHA256(enc_key)`. The resulting table
is verified to be a bijection (every byte appears exactly once), and an
inverse table is built for decryption.

### 1.4 Key Schedule

The 256-bit encryption key is expanded into `(NR + 1) × 4` 32-bit round
keys using an AES-256-style schedule:

```
RotWord -> SubWord (via dynamic S-Box) -> XOR with Rcon
```

### 1.5 Key Derivation and File Format

```
File format:
  [16-byte salt][16-byte nonce][ciphertext][32-byte HMAC-SHA256]
```

`PBKDF2-HMAC-SHA256(password, salt, 100000)` produces 64 bytes, split
into:

* `enc_key` (32 bytes) — drives the block cipher and S-Box
* `mac_key` (32 bytes) — used for HMAC-SHA256 authentication

The HMAC is computed over the original plaintext and appended before CTR
encryption. On decryption the HMAC is recomputed and compared.

### 1.6 Decoy Mode (Experimental)

By default, a wrong password causes `choidec` to report an authentication
failure and write no output. With `--decoy`, `choidec` writes a
**deterministic decoy** stream for the same ciphertext instead.

This is **not** full Honey Encryption. Real Honey Encryption requires a
Distribution-Transforming Encoder (DTE) that knows the plaintext space;
Choicrypt operates on arbitrary binary files, so such a construction is
not possible here. The decoy mode is provided only as an experimental
brute-force confusion aid and has known limitations (see Security
Analysis).

---

## 2. Project Layout

| File | Purpose |
|------|---------|
| `choi_common.h` | SHA-256, HMAC, PBKDF2, SP-network block cipher, CTR transform, decoy generator |
| `choi_enc.c` | File encryption tool |
| `choi_dec.c` | File decryption tool (with optional `--decoy`) |
| `virtual_silicon.c` / `.h` | Twisted-computation mini-VM: 16 registers, 4 banks, key-dependent ISA, self-modifying bytecode |
| `dynamic_asm.c` / `.h` | Four-operation invertible dynamic round module |
| `obfuscated_pipeline.c` / `.h` | Reversible obfuscation pipeline (P-Box + VM bytecode + rolling keys) |
| `poc.c` | Proof-of-concept / verification demo |
| `tests/` | Unit tests for block, CTR, virtual silicon, and decoy |
| `crypt_hardcore_audit.py` | Statistical audit (chi-square, autocorrelation, NIST-style tests) |
| `check_safety.sh` | Integrated build / test / round-trip / audit script |
| `blueprints/` | Technical specification documents |

---

## 3. Build and Usage

### 3.1 Build

```bash
make all        # choienc, choidec, choi_poc  (enables -mssse3 on x86-64)
make test       # build and run unit tests
make clean      # remove all binaries and artifacts
```

### 3.2 Encrypt a File

```bash
echo 'my_password' | ./choienc secret.txt
# creates secret.txt.choi
```

### 3.3 Decrypt a File

```bash
echo 'my_password' | ./choidec secret.txt.choi decrypted.txt
# or omit the .choi extension:
echo 'my_password' | ./choidec secret.txt decrypted.txt
```

### 3.4 Decoy Mode

```bash
echo 'wrong_password' | ./choidec --decoy secret.txt.choi fake_output.txt
```

### 3.5 Run Verification

```bash
./choi_poc          # interactive proof-of-concept demo
./check_safety.sh   # full build + test + audit suite
```

---

## 4. Security Analysis

### 4.1 What Choicrypt Provides

* **Key-dependent confusion**: the S-Box changes with every password,
  complicating attacks that rely on a fixed substitution table.
* **Diffusion**: `ShiftRows`, `MixColumns`, and the `HexagonalLayer`
  propagate single-byte changes across the entire 128-bit block.  The
  antipodal shuffle adds a non-linear geometric mixing step on top of the
  standard SP-network diffusion.
* **Brute-force resistance**: PBKDF2-HMAC-SHA256 with 100,000 iterations
  slows password guessing.
* **Per-file uniqueness**: random salt and nonce ensure that encrypting
  the same file twice produces different ciphertexts and prevents
  keystream reuse.
* **Authentication**: HMAC-SHA256 detects tampering and wrong passwords.

### 4.2 Known Limitations and Attack Surface

| Concern | Status |
|---------|--------|
| Custom cipher | Not peer-reviewed; avoid for production |
| AEAD | Not used; only HMAC for authentication |
| Side-channel resistance | No constant-time guarantees; timing/cache analysis may be possible |
| Decoy mode | Deterministic and distinguishable from real plaintext in general |
| Quantum computing | Grover's algorithm reduces effective key security, as with AES-256 |
| Related-key attacks | Not formally analyzed |

### 4.3 When to Use What

| Scenario | Recommendation |
|----------|----------------|
| Learning / CTF / obfuscation research | Choicrypt (experimental) |
| Personal token storage with clear failure | Choicrypt + strong password |
| Production databases / TLS / regulated data | **AES-256-GCM** or **ChaCha20-Poly1305** |

---

## 5. Verification

The repository includes several verification mechanisms:

* **Unit tests** (`make test`): block round-trip, CTR properties, VM
  behaviour, decoy determinism.
* **PoC** (`./choi_poc`): avalanche, HMAC authentication, VM operations,
  dynamic ASM, obfuscated pipeline round-trips.
* **Statistical audit** (`crypt_hardcore_audit.py`): chi-square,
  autocorrelation, key independence, monobit, runs, block-frequency.
* **Integration script** (`check_safety.sh`): builds everything, checks
  encryption/decryption integrity, tests wrong-password rejection and
  decoy mode, and runs the audit.

---

## 6. License and Disclaimer

This project is provided for educational and research purposes only.
Because Choicrypt is a custom cipher without independent cryptanalysis,
the authors make no security claims for any real-world use. Always prefer
established, standardized cryptographic libraries for sensitive data.
