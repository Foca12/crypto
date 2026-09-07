# Description

This is an implementation of the SHA algorithm, written for educational purposes. This implementation provides SHA-256.

## Features

- **SHA-256**: Full support for hashing
- **Core Operations**:
  - Message padding and parsing (handles bit/byte alignments)
  - Message schedule generation (W0-W63 extension blocks)
  - Standard logical functions (Ch, Maj, $\Sigma_0$, $\Sigma_1$, $\sigma_0$, $\sigma_1$) and 32-bit word operations
- **Consistent Output**: Generates compliant 256-bit (32-byte) message digests

> Note: This project is educational. Do not use this code in production. See SECURITY.md for details.

## Compilation

```bash
g++ -std=c++17 -o aes_crypt examples/cbc/example1.cpp
```

## Examples

See `examples/` for examples.

# 📂 Project Structure

```
crypto/
├── src/
│   └── sha/                     # Implementation of SHA and core functions
│       ├── hash.hpp             # Main hashing functions
│       ├── sha_helpers.hpp      # Helper functions, type definitions and constants
│       ├── message.hpp          # Message split into 64 byte blocks
│       └── chunk.hpp            # SHA 64 byte chunk
|
└── markdowns/
    └── sha/                     # SHA markdowns
        ├── FEATURES.md          # A file explaining the SHA's features
        └── SECURITY.md          # SHA's security disclaimer

```

# 🔧 Available Functions

## SHA 256 hashing digested in Bytearray

```cpp
Bytearray sha256_hash(Bytearray message)
```

# How SHA Works

SHA-256 is a **cryptographic hash function** which produce a unique 256-bit message digest.

The core pipeline operates as follows:

1. **Padding**: The input message is padded with a single bit `1`, followed by `0` bits, and ends with a 64-bit block representing the original message length in bits. This ensures the total length is a multiple of 512 bits.
2. **Parsing**: The padded message is sliced into $N$ blocks of 512 bits. Each block is further split into sixteen 32-bit words.
3. **Message Schedule ($W$)**: The 16 initial words are expanded into an array of 64 words ($W_0$ to $W_{63}$) using specific bitwise logical functions, right rotations (`ROTR`), and right shifts (`SHR`).
4. **Compression Loop**: The algorithm initializes 8 working registers ($A, B, C, D, E, F, G, H$) with specific fractional parts of the square roots of the first 8 prime numbers. For 64 rounds, these registers are mixed using:
   - Bitwise logical functions: `Ch` (Choose) and `Maj` (Majority).
   - Sigma functions ($\Sigma_0, \Sigma_1$) based on complex modular rotations.
   - Round constants ($K_t$) derived from the cube roots of the first 64 prime numbers.
   - The expanded message words ($W_t$).
5. **Final Cascade**: After processing all blocks, the final values of the working registers are concatenated into a hexadecimal string to form the final 256-bit hash.

# Educational Note

This code was written for educational purposes to help understand the details of the SHA algorithm. For real-world security applications, use proven cryptographic libraries such as **OpenSSL** or **libsodium**.

---

See also ./SECURITY.md

**Made with ❤️ from Foca12**
