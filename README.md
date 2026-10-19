# 🦀 Arypto

> **Multi-layer file encryption in Rust.** Because why not.

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## 🧠 What is this?

Arypto is a **multi-layer (cascade) file encryption tool** written in Rust. Instead of using just one cipher, it chains **7 different encryption algorithms** in series, with a **separate derived key for each layer**.

> ⚠️ **Status:** Experimental, educational, and built for fun. **No security audit.** Use at your own risk.

---

## 🔐 Encryption Pipeline

### 1. Key Derivation
- **Master key** derived from password using **Argon2id**
- **Per-cipher keys** derived using:
  - BLAKE3 (keyed mode)
  - HMAC-SHA256
  - HMAC-Streebog256 + HMAC-JH256 (two-layer combo)

### 2. Cascade Encryption (7 layers)
The encryption order is:
1. **Camellia** (CTR, 256-bit)
2. **ASCON** (AEAD, 128-bit)
3. **Serpent** (CTR, 256-bit)
4. **XChaCha20** (Poly1305, 256-bit)
5. **Twofish** (256-bit)
6. **AES** (GCM, 256-bit)
7. **Threefish** (1024-bit)

Each layer appends its **nonce/IV** to the output, and the next layer encrypts the whole thing.

### 3. Post-Quantum Signatures
- **ML-DSA** (Module-Lattice-Based Digital Signature) signs after the first layer.
- **SLH-DSA** (Stateless Hash-Based Digital Signature) signs at the very end.
- Both signatures are verified during decryption.

### 4. Key Storage 
- The **ML-DSA seed** and **SLH-DSA keypair** are stored in the **OS keyring** (via the `keyring` crate).
- If you decrypt without the keyring, **signature verification is skipped** (with a warning).

### 5. Output Format
- The final encrypted file is **Base64-encoded**.
- Encrypted file contains: ciphertext + nonces + salts + signatures.

### 6. Memory Safety
- The code uses `memmap2` for efficient file reading.
- The code uses `zeroize`.
---
| # | Cipher | Mode | Key Size | Notes |
|---|--------|------|----------|-------|
| 1 | Camellia | CTR | 256-bit | First layer |
| 2 | ASCON | AEAD | 128-bit | |
| 3 | Serpent | CTR | 256-bit | |
| 4 | XChaCha20 | Poly1305 | 256-bit | |
| 5 | Twofish | CTR | 256-bit | |
| 6 | AES | GCM | 256-bit | |
| 7 | Threefish | CTR | 1024-bit | Final layer |
---
### Disclaimer
> This is not production-ready. It has not been audited.
---

## 🚀 Usage

```bash
# Clone
git clone https://github.com/ar7sha/arypto.git
cd arypto

# Build
cargo build --release

# Encrypt
./target/release/arypto -e input.txt output.enc

# Decrypt
./target/release/arypto -d output.enc decrypted.txt
