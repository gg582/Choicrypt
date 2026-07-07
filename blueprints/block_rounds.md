# Block Cipher Round Logic

Choicrypt is a 128-bit SP-network block cipher with 14 rounds. The design
follows the standard Substitution–Permutation structure while replacing
the fixed AES S-Box with a key-dependent dynamic S-Box.

## State Layout

The 16-byte block is viewed as a 4x4 matrix of bytes in row-major order:

```
[ s0  s4  s8  s12 ]
[ s1  s5  s9  s13 ]
[ s2  s6  s10 s14 ]
[ s3  s7  s11 s15 ]
```

## Round Function (rounds 1..13)

```
SubBytes(state)        -- dynamic S-Box
ShiftRows(state)       -- cyclic row shifts
MixColumns(state)      -- GF(2^8) matrix multiplication
AddRoundKey(state, r)  -- XOR with round key
```

## Final Round (round 14)

```
SubBytes(state)
ShiftRows(state)
AddRoundKey(state, 14)
```

`MixColumns` is omitted in the final round, exactly as in AES.

## Inversion

Each layer is individually invertible:

| Forward | Inverse |
|---------|---------|
| SubBytes | InvSubBytes (dynamic inverse S-Box) |
| ShiftRows | InvShiftRows |
| MixColumns | InvMixColumns |
| AddRoundKey | AddRoundKey (XOR is self-inverse) |

Decryption applies the inverse layers in reverse order:

```
AddRoundKey(state, 14)
for r = 13 .. 1:
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, r)
    InvMixColumns(state)
InvShiftRows(state)
InvSubBytes(state)
AddRoundKey(state, 0)
```

## MixColumns Details

MixColumns multiplies each column by the AES MDS matrix over GF(2^8)
with irreducible polynomial `0x11B`:

```
| 02 03 01 01 |   | s0 |   | s0' |
| 01 02 03 01 |   | s1 |   | s1' |
| 01 01 02 03 | * | s2 | = | s2' |
| 03 01 01 02 |   | s3 |   | s3' |
```

InvMixColumns uses the inverse matrix:

```
| 0e 0b 0d 09 |
| 09 0e 0b 0d |
| 0d 09 0e 0b |
| 0b 0d 09 0e |
```

## Avalanche

Single-bit changes in plaintext or key should affect roughly half of the
output bits after a full encryption. The unit tests and PoC verify that
the avalanche effect stays within a reasonable range.
