# Virtual Silicon VM

The `virtual_silicon.c` module implements a small bytecode virtual machine
with a deliberately twisted computation space. It is an **experimental**
obfuscation/structural layer; real entropy and key-stretching security
still rely on `/dev/urandom`, HMAC-SHA256, and PBKDF2.

## VM Architecture

* **Registers**: 16 general-purpose registers, each 16 bytes.
* **Banks**: Registers are grouped into 4 banks of 4 registers each.
  Instructions use *bank-relative* register indices, and the active bank
can be switched at runtime.
* **Program counter**: 8-bit.
* **Obfuscation state**: 8-bit value that twists the meaning of opcodes
dynamically.
* **Key-dependent ISA**: A 256-byte opcode mapping table derived from a key.
  The same raw bytecode byte can mean completely different operations
under different keys.
* **Rewrite buffer**: 256-byte workspace for self-modifying bytecode.
  Unwritten slots are read as zero.

## Opcode Set

| Opcode | Description |
|--------|-------------|
| `NOP` | No operation |
| `LOAD` | Load 16 immediate bytes into a register |
| `STORE` | Mark register as externally observable |
| `XOR` | XOR every byte of a register with an immediate |
| `ROL` | Rotate every byte of a register left by an immediate |
| `SUB` | Subtract an immediate from every byte of a register |
| `SBOX` | Apply the VM's fixed S-Box to a register |
| `MIX` | XOR a register with another and rotate left by 1 |
| `ENTROPY` | Read 16 bytes from `/dev/urandom` |
| `HMAC_STEP` | Compute `HMAC-SHA256(R_key, R_msg) -> R_out` |
| `OBF` | Update the opcode-twisting state |
| `BANK` | Switch the active register bank |
| `PATCH` | Self-modifying bytecode: XOR N bytes of the execution image with `R0` |
| `HALT` | Stop execution |

## Addressing

A register operand is resolved as:

```
physical_index = (active_bank * 4) + (operand % 4)
```

So `R1` in bank 0 is physical register 1, while `R1` in bank 2 is physical
register 9.

## Key-Dependent ISA

With `vs_vm_init_keyed(key)`, the 256 raw opcode values are permuted using a
Fisher–Yates shuffle seeded by the key. Runtime resolution then applies an
additional twist:

```
effective_opcode = opcode_map[raw] XOR obf_state + obf_state
```

The same bytecode program therefore decodes to different operations under
different keys, and the decode changes as the obfuscation state evolves.

## Self-Modifying Bytecode

`PATCH start count` XORs `count` bytes of the execution image (starting at
`start`) with the current value of `R0`. Reads from unwritten rewrite-buffer
slots are treated as zero; writes always go into the rewrite buffer, which is
logically appended immediately after the original bytecode.

This lets a program rewrite itself while it runs, further twisting the
execution space.

## Provided Operations

### VM CSPRNG

`vs_rng_bytes(seed, out, len)` executes a deterministic bytecode loop that
uses bank switching and non-linear mixing, feeding the output back as the
next seed. The seed should come from `/dev/urandom`.

### VM KDF Wrapper

`vs_kdf(password, salt, iterations, out, outlen)` runs a short VM program on
a HMAC-derived seed, then delegates the actual key-stretching to
PBKDF2-HMAC-SHA256.

### VM Obfuscation

`vs_obfuscate_block(key, block)` applies a self-inverse bytecode sequence to
the block. The sequence uses only self-inverse operations (XOR and ROL by 4),
so applying it twice restores the original block.

## Security Note

The VM layer is intentionally experimental. It has **not** been proven to add
concrete security against a motivated adversary and may increase
implementation complexity. Use it for research and obfuscation experiments,
not as a replacement for standard authenticated encryption.
