# goRecrypt

`goRecrypt` is a high-performance Go library that provides a suite of advanced cryptographic tools, centered around Proxy Re-Encryption (PRE). It enables secure and flexible data sharing in decentralized systems.

## Features
*   **Proxy Re-Encryption (PRE)**: Allows a proxy to re-encrypt data from one key to another without having access to the underlying plaintext or private keys.
*   **Threshold PRE**: Enhances security by splitting the re-encryption key among multiple proxies, requiring a threshold `t-of-n` to perform re-encryption. This eliminates single points of trust and failure.
*   **Hierarchical Deterministic (HD) Keys**: Implements BIP32-style key derivation, allowing for the creation of a tree of keys from a single master seed. This is essential for wallet applications and managing multiple user keys.
*   **Secure Keystore**: Provides Ethereum-style, password-protected JSON keystores for securely storing private keys using `scrypt` and AES.
*   **Curve Support**: Supports standard NIST curves (`P-256`, `P-384`, `P-521`) and the `secp256k1` curve used by Bitcoin and Ethereum.
