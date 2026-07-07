# Key Initialization and Derivation

## Password-Based Key Derivation

Choicrypt derives key material from a user password with
**PBKDF2-HMAC-SHA256**:

```
master = PBKDF2-HMAC-SHA256(password, salt, iterations=100000, length=64)
enc_key = master[0..31]
mac_key = master[32..63]
```

* A fresh 16-byte `salt` is read from `/dev/urandom` for every file.
* The salt is stored in the file header; it is not secret.
* The iteration count is fixed at 100,000.

## Encryption Key Processing

1. `enc_key` is hashed with SHA-256 to seed the dynamic S-Box shuffle.
2. The same `enc_key` is expanded into round keys with an AES-256-style
   key schedule, using the dynamic S-Box for `SubWord` operations.

## Key Schedule

For a 256-bit master key and 14 rounds, 60 32-bit words are produced:

```
W[0..7]  = enc_key
for i = 8 .. 59:
    temp = W[i-1]
    if i mod 8 == 0:
        temp = SubWord(RotWord(temp)) XOR (Rcon[i/8] << 24)
    else if i mod 8 == 4:
        temp = SubWord(temp)
    W[i] = W[i-8] XOR temp
```

`SubWord` applies the dynamic S-Box to each byte of the word.

## MAC Key

`mac_key` is used directly as the key for HMAC-SHA256 authentication.
