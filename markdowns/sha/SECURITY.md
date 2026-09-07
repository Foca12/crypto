# Security Notice

This repository contains an educational implementation of SHA 256 in C++ and is intended only for educational purposes, experimentation, and study.

DO NOT use this code in production or to protect sensitive data.

## 🔐 SHA-256 Security Analysis & Educational Overview

SHA-256 is designed to act as a **cryptographic one-way function**. To understand how it secures data mathematically, its implementation must satisfy three core properties:

- Pre-image Resistance (One-Way Property)

* **Concept:** Given a hash output $H$, it must be computationally impossible to reverse the process to find the original input message $M$ such that $\text{SHA-256}(M) = H$.
* **Mechanism:** SHA-256 achieves this through a 64-round compression loop. It utilizes heavily non-linear logical functions (`Ch` and `Maj`) mixed with irreversible modular addition ($\pmod{2^{32}}$). Every round cascades the bits so thoroughly that reversing the mathematical operations back to the input would require a brute-force search of $2^{256}$ steps.

- Second Pre-image Resistance

* **Concept:** Given a specific input message $M_1$, it must be computationally impossible to find a _different_ input message $M_2$ such that $\text{SHA-256}(M_1) = \text{SHA-256}(M_2)$.
* **Mechanism:** This prevents an attacker from intercepting a valid message or file, altering its contents, and keeping the exact same hash signature to bypass validation checks.

- Collision Resistance

* **Concept:** It must be computationally impossible to find _any two distinct messages_ $M_1$ and $M_2$ anywhere that produce the exact same output, such that $\text{SHA-256}(M_1) = \text{SHA-256}(M_2)$.
* **The Birthday Paradox:** Due to the mathematical birthday bound, finding _any_ generic collision requires roughly $2^{128}$ operations (instead of $2^{256}$). SHA-256 remains completely unbroken: no practical or theoretical collision has ever been found against the full 64-round algorithm.

### The Vulnerability

If you attempt to build a naive Message Authentication Code (MAC) by simply concatenating a secret key with a message:
$$\text{Incorrect-MAC} = \text{SHA-256}(\text{Key} \parallel \text{Message})$$

An attacker who intercepts this hash and knows the length of the message (but **not** the secret key) can use the final state of the SHA-256 registers to append extra data to the end of the message. They can then calculate a perfectly valid hash for the new, altered payload without ever knowing the key.

### The Solution (HMAC)

To securely authenticate messages using SHA-256, you must never use simple concatenation. Instead, you must implement **HMAC-SHA256** (Hash-based Message Authentication Code), which nests the hashing process into two distinct layers using inner (`ipad`) and outer (`opad`) padding constants:
$$\text{HMAC}(K, M) = \text{SHA-256}\big((K \oplus \text{opad}) \parallel \text{SHA-256}((K \oplus \text{ipad}) \parallel M)\big)$$

## Raccomandations

If you are writing production code use a secure library such as OpenSSL, libsodium, BoringSSL or Botan

## Limitation of liability

THE MAINTAINER ASSUMES NO LIABILITY FOR DAMAGES ARISING FROM THE USE OF THIS SOFTWARE. USE IS AT THE USER'S OWN RISK.

---

Foca12 — 2026
