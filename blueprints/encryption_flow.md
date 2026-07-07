# Encryption / Decryption Flow

Choicrypt uses a CTR-like mode with a 128-bit block cipher. The file
format is:

```
[salt (16 bytes)][nonce (16 bytes)][ciphertext][HMAC-SHA256 (32 bytes)]
```

## Encryption Pipeline

```
Password
    |
    v
PBKDF2-HMAC-SHA256(salt, 100000 iters)
    |
    +---> enc_key (32 bytes) ---> dynamic S-Box + key schedule
    +---> mac_key (32 bytes)

Plaintext
    |
    v
HMAC-SHA256(mac_key, plaintext) ---> tag
    |
    v
Payload = plaintext || tag
    |
    v
CTR XOR with keystream = choi_encrypt_block(nonce || counter)
    |
    v
File = salt || nonce || ciphertext || tag (encrypted as part of payload)
```

## Decryption Pipeline

```
File
    |
    +---> salt  ---> derive enc_key/mac_key
    +---> nonce ---> initialise counter
    +---> payload

Payload
    |
    v
CTR XOR with keystream
    |
    +---> plaintext
    +---> stored HMAC tag

Recompute HMAC(mac_key, plaintext)
    |
    +---> match    ---> output plaintext
    +---> mismatch ---> report failure (or write decoy if --decoy)
```

## Counter Format

The 16-byte counter is initialised with the nonce in the first
`CHOI_NONCE_SIZE` bytes and zero in the remaining bytes. It is
incremented as a big-endian 128-bit integer after each block.
