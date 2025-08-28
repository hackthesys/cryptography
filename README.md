# 🦀 Rust Crypto CLI Tools

This is a Rust workspace containing multiple command-line tools for learning, implementing, and analyzing various cryptographic techniques. Each module corresponds to a cryptography lecture or concept, implemented as a separate Rust binary crate.

## ✨ Features

- **Interactive CLI**: Intuitive command-line interface built with the `clap` crate for straightforward usage.
- **File Support**: Easily read input from and write output to files, making it script- and automation-friendly.
- **Modular Architecture**: Designed for extensibility — new cryptographic tools can be added with minimal effort.


### ✅ Progress Tracker

- [x] **Additiv** - Additive cipher implementation and analysis.
- [x] **Vigenère** - Vigenère cipher CLI tool with encryption/decryption.
- [x] **Betriebsmodi** - Block cipher modes of operation (ECB, CBC, etc.).
- [x] **AES** - Implementation or interface for AES encryption.
- [x] **Schlüsselgenerierung** - Key generation algorithms and utilities.
- [x] **Lineare Analyse** - Tools for linear cryptanalysis.
- [x] **Güte von linearen Approximationen** - Evaluation of linear approximation quality.
- [x] **RSA** - RSA algorithm basics: encryption/decryption.
- [x] **RSA Key** - RSA key generation and management tools.
- [ ] **Diffie-Hellman** - Key exchange protocol implementation and utilities
- [x] **SHA-3** - SHA-3 hash function implementation and analysis.
- [ ] **DSA** - Digital Signature Algorithm implementation and verification tools.

## Getting Started

### Prerequisites

- Rust (version 1.65 or later)
- Cargo (Rust's package manager)

## 🛠 Build Instructions

clone the repository and build the workspace in release mode:

```bash
git clone <repository-url>
cd <project-directory>
cargo build --release
```
