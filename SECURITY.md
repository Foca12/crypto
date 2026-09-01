# Security Notice

This repository contains an educational implementation of multiple algorithms in C++ and is intended only for educational purposes, experimentation, and study.

DO NOT use this code in production or to protect sensitive data.

## What this means

- This library is educational: it is designed to help understand the internal mechanisms of AES and encryption modes.
- Do not expose keys, IVs/nonces, or plaintext in logs.
- Default choices (encryption modes, padding, nonce management) may not be suitable for all security scenarios.

## Specific algorithms

If you are looking for a more detailed description and security info about a specific algorithm, you can find them in markdowns/algorithm-name

## Recommendations

If you are writing production code use a secure library such as OpenSSL, libsodium, BoringSSL or Botan

## Limitation of liability

THE MAINTAINER ASSUMES NO LIABILITY FOR DAMAGES ARISING FROM THE USE OF THIS SOFTWARE. USE IS AT THE USER'S OWN RISK.

---

Foca12 — 2026
