# Crypto - Educational Encryption Library

An educational header-only library written in C++ that implements different encryption algorithms from scratch.

**Created by:** Foca12
**Creation date:** 2026  
**Language:** C++

## Description

This library is still in development. Currently, it provides an implementation of the encryption algorithm AES 128, 192 and 256 in ECB and CBC modes

## Features

### AES

- **AES-128**: ECB and CBC support for 128-bit encryption
- **AES-192**: ECB and CBC support for 192-bit encryption
- **AES-256**: ECB and CBC support for 256-bit encryption
- **Cryptographic Operations**:
  - SubBytes (byte substitution)
  - ShiftRows (row rotation)
  - MixColumns (column mixing)
  - AddRoundKey (XOR with the round key)
- **Key Expansion**: Automatic generation of round keys (11 round keys for AES-128, 13 for AES-192, 15 for AES-256)
- **Encryption and Decryption**: Full support for both operations
- **Header-only public API**: Full internal state management exposure, no need for separate compilation

> Note: This project is educational. Do not use this code in production. See SECURITY.md for details.

## Usage

This library is header-only — include headers in include/ to use the library (no separate compilation required).

### Compilation

```bash
g++ -std=c++17 -o aes_crypt examples/cbc/example1.cpp
```

### Examples

See `examples/` for examples.

## 📂 Project Structure

```
crypto/
├── src/                     # Implementation of multiple algorithms and core functions
│
├── include/                 # Header-only public API
│   └── bytearray.hpp        # /src/bytearray.hpp header
│
├── examples/
│   └── aes/                 # aes examples
│
├── README.md                # This readme
├── SECURITY.md              # Security disclaimer
└── LICENSE                  # MIT License

```

## License

This project is distributed under the **MIT License**—see the [LICENSE](LICENSE) file for details.

Copyright © 2026 Foca12

## Educational Note

This code was written for educational purposes to help understand the details of the AES algorithm. For real-world security applications, use proven cryptographic libraries such as **OpenSSL** or **libsodium**.

---

See also SECURITY.md

**Made with ❤️ by Foca12**
