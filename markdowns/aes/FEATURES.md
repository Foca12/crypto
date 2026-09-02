# Description

This is an implementation of the AES algorithm, written for educational purposes. This implementation provides AES-128, AES-192 and AES-256 support in ECB, CBC and CTR modes.

## Features

- **AES-128**: ECB, CBC and CTR support for 128-bit encryption
- **AES-192**: ECB, CBC and CTR support for 192-bit encryption
- **AES-256**: ECB, CBC and CTR support for 256-bit encryption
- **Cryptographic Operations**:
  - SubBytes (byte substitution)
  - ShiftRows (row rotation)
  - MixColumns (column mixing)
  - AddRoundKey (XOR with the round key)
- **Key Expansion**: Automatic generation of round keys (11 round keys for AES-128, 13 for AES-192, 15 for AES-256)
- **Encryption and Decryption**: Full support for both operations
- **Header-only public API**: Full internal state management exposure, no need for separate compilation

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
│   └── aes/                     # Implementation of AES and core functions
│       ├── encrypt.hpp          # Main encryption functions
│       ├── helpers.hpp          # Helper functions, type definitions and constants
│       ├── message.hpp          # Message split into 16 byte blocks
│       ├── key.hpp              # Key management and expansion
│       ├── state.hpp            # State matrix implementation
│       └── crypt/               # Cryptographic functions
│           ├── add_round_key.hpp
│           ├── sub_bytes.hpp
│           ├── shift_rows.hpp
│           └── mix_columns.hpp
|
└── markdowns/
    └── aes/                     # AES markdowns
        ├── FEATURES.md          # A file explaining the AES's features
        └── SECURITY.md          # AES's security disclaimer

```

# 🔧 Available Functions

## Multi-Size AES Encryption in ECB, CBC and CTR modes

```cpp
Bytearray encrypt_aes(Bytearray message, const Key& key)
Bytearray encrypt_aes(Bytearray message, const Key& key, const State& iv, const Mode& mode)
```

## Multi-Size AES Decryption in ECB, CBC and CTR modes

```cpp
Bytearray decrypt_aes(Bytearray encrypted, const Key& key)
Bytearray decrypt_aes(Bytearray encrypted, const Key& key, const State& iv, const Mode& mode, bool remove_padding = true)
```

# How AES Works

AES is a symmetric encryption algorithm that uses:

1. **SubBytes**: Nonlinear substitution of each byte
2. **ShiftRows**: Rotation of the rows of the state matrix
3. **MixColumns**: Mixing of columns for diffusion
4. **AddRoundKey**: XOR with the round key
5. **Key Expansion**: Generation of 11 (AES-128), 13 (AES-192) or 15 (AES-256) round keys

For more information: [NIST AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

# Encryption modes

- **ECB (Electronic CodeBook)**: Simple modes where each block is encrypted independently. ⚠️ Less secure for repeated patterns.

- **CBC (Cipher Block Chaining)**: Each block is XORed with the previous ciphertext block before encryption, providing better security properties.

- **CTR (Counter)**: Turns the block cipher into a stream cipher. It encrypts a continuously incrementing counter and XORs the result with the plaintext. It does not require padding.

# Educational Note

This code was written for educational purposes to help understand the details of the AES algorithm. For real-world security applications, use proven cryptographic libraries such as **OpenSSL** or **libsodium**.

---

See also ./SECURITY.md

**Made with ❤️ from Foca12**
