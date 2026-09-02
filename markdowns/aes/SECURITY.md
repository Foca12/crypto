# Security Notice

This repository contains an educational implementation of AES (128/192/256) in ECB, CBC and CTR mode in C++ and is intended only for educational purposes, experimentation, and study.

DO NOT use this code in production or to protect sensitive data.

## Why AES ECB isn't secure

This implementation provides ECB, CBC and CTR mode. ECB is insecure for multi-block data: identical plaintext blocks encrypt to identical ciphertext blocks, which leaks plaintext structure and enables tampering. Do not use ECB in production — use an authenticated mode such as AES-GCM or ChaCha20-Poly1305 instead.

### Why AES CBC requires caution

This library also implements CBC (Cipher Block Chaining) mode. While CBC solves the pattern-leakage problem of ECB by XORing each plaintext block with the previous ciphertext block, it carries its own significant production risks:

- **Malleability:** CBC does not provide data integrity. An attacker can alter bytes in a ciphertext block to predictably modify the decrypted plaintext of the next block.
- **Padding Oracle Attacks:** Because CBC relies on standard padding (like PKCS#7), implementations that leak timing or error details during decryption are highly vulnerable to Padding Oracle attacks, allowing an attacker to decrypt the ciphertext without knowing the key.
- **IV Requirements:** CBC requires a cryptographically secure, unpredictable Initialization Vector (IV) for every encryption session. Reusing an IV destroys the security guarantees of the mode.

### Why AES CTR requires caution

This library also implements CTR (Counter) mode. While CTR turns AES into a stream cipher—eliminating the need for padding and allowing parallel execution—it introduces a critical single point of failure:

- **The Two-Time Pad Catastrophe:** The security of CTR mode relies entirely on the uniqueness of the keystream. If you encrypt two different messages using the same Key and the same Initialization Vector/Nonce, an attacker can XOR the two ciphertexts together to completely cancel out the encryption, leaking the plaintext of both messages.
- **Bit-Flipping Attacks:** Like CBC, CTR does not provide integrity (it is not authenticated). Since it operates as a stream cipher, an attacker who knows or guesses part of the plaintext can flip specific bits in the ciphertext to precisely alter the decrypted message without triggering any error.

## Raccomandations

If you are writing production code use a secure library such as OpenSSL, libsodium, BoringSSL or Botan

## Limitation of liability

THE MAINTAINER ASSUMES NO LIABILITY FOR DAMAGES ARISING FROM THE USE OF THIS SOFTWARE. USE IS AT THE USER'S OWN RISK.

---

Foca12 — 2026
