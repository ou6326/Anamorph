# Project Anamorph

> **COMP6453** — Applied Cryptography Project
> University of New South Wales

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-blue)](https://github.com/)
[![Language: Rust](https://img.shields.io/badge/language-Rust-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Background & Motivation](#2-background--motivation)
3. [Threat Model](#3-threat-model)
4. [Architecture](#4-architecture)
5. [Getting Started](#5-getting-started)
6. [Crate Dependencies](#6-crate-dependencies)
7. [Usage](#7-usage)
8. [Testing & Benchmarking](#8-testing--benchmarking)
9. [Team & Responsibilities](#9-team--responsibilities)
10. [Project Timeline](#10-project-timeline)
11. [References](#11-references)

---

## 1. Project Overview

**Project Anamorph** is the first open Rust implementation of the _Unsynchronized Robustly Anamorphic ElGamal_ scheme, originally introduced at [EUROCRYPT 2022](#11-references) and extended with the strengthened robustness model of [Banfi et al. (EUROCRYPT 2024)](#11-references).

The scheme provides a **covert communication channel** hidden inside syntactically normal ElGamal ciphertexts. Even under full key-extraction by a coercive adversary, the existence of the covert channel remains undetectable.

### Key Features

- Full **Normal Mode** and **Anamorphic Mode** (EC22 base scheme + EC24 extension)
- **Multi-use double keys** — resolving the one-shot limitation of EC22
- **Covert-message presence indicator** — PRF-mode packets can be checked for a candidate covert payload, while normal packets cleanly report no covert payload
- **HMAC-SHA256 MAC helpers** — hardened generation and verification primitives
- **Constant-time helper module** for secret-dependent operations
- **Block-padding** support for length-oracle mitigation
- Empirical **benchmarks** measuring anamorphic overhead vs. covert payload size

---

## 2. Background & Motivation

Traditional public-key encryption is entirely broken when an adversary can compel a user to surrender their secret key. **Anamorphic cryptography**, introduced by Persiano, Phan, and Yung (2022), addresses this by embedding a mathematically guaranteed covert channel _inside_ ordinary ciphertexts — without any visible deviation from normal operation.

This project implements and extends that construction to address two limitations of the original scheme:

| Limitation (EC22)                                              | Resolution (EC24 Extension)                               |
| -------------------------------------------------------------- | --------------------------------------------------------- |
| Double key can only be established once at key-generation time | Multi-use double keys, re-establishable without re-keying |
| Receiver cannot tell if a ciphertext carries a covert message  | Covert-message presence indicator                         |

---

## 3. Threat Model

Two coercion types are formally characterised:

| Type                | Description                                                           |
| ------------------- | --------------------------------------------------------------------- |
| **Type-1 Coercion** | Adversary compels the _receiver_ to surrender their secret key        |
| **Type-2 Coercion** | Adversary forces the _sender_ to transmit a specific chosen plaintext |

Under both coercion types, the normal-mode ciphertext remains syntactically and semantically indistinguishable from a ciphertext that carries no covert payload. The adversary cannot distinguish the two cases even with full key material.

**CCA Vulnerability Surface:** The implementation formally characterises the anamorphic-CCA attack surface of the ElGamal construction and evaluates whether HMAC-SHA256 MAC verification closes the gap identified in recent literature.

---

## 4. Architecture

```
project-anamorph/
├── src/
│   ├── lib.rs                  # Public API surface
│   ├── params.rs               # Safe prime & generator generation
│   ├── errors.rs               # Unified error model
│   ├── normal/
│   │   ├── mod.rs
│   │   ├── keygen.rs           # Gen()
│   │   ├── encrypt.rs          # Enc()
│   │   └── decrypt.rs          # Dec()
│   ├── anamorphic/
│   │   ├── mod.rs
│   │   ├── keygen.rs           # aGen()
│   │   ├── encrypt.rs          # aEnc()
│   │   └── decrypt.rs          # aDec()
│   ├── ec24/
│   │   ├── mod.rs              # EC24 robustness extension
│   │   ├── double_key.rs       # Multi-use double key protocol
│   │   └── indicator.rs        # Covert-message presence indicator
│   ├── hardening.rs            # HMAC-SHA256 MAC generation/verification primitives
│   ├── padding.rs              # Block-padding (length oracle mitigation)
│   └── ct.rs                   # Constant-time helpers (via subtle)
├── benches/
│   └── throughput.rs           # Criterion benchmarks
├── tests/
│   ├── normal_mode.rs
│   ├── anamorphic_mode.rs
│   ├── coercion_simulation.rs  # Type-1 and Type-2 coercion tests
│   ├── indistinguishability.rs # proptest harness
│   └── behavior_comparison.rs  # Legacy vs secure behavior and tampering comparisons
├── scripts/
│   └── plot_benchmarks.py      # Python post-processing for Criterion output
├── Cargo.toml
├── Cargo.lock
├── Makefile
└── README.md
```

### Mode Comparison

|                | Normal Mode      | Anamorphic Mode                              |
| -------------- | ---------------- | -------------------------------------------- |
| Key generation | `Gen(λ)`         | `aGen(λ)` — produces public key + double key |
| Encryption     | `Enc(pk, m)`     | `aEnc(pk, dk, m, m_covert)`                  |
| Decryption     | `Dec(sk, c)`     | `aDec(sk, dk, c)` — recovers both messages   |
| Ciphertext     | Standard ElGamal | Syntactically identical to normal            |

---

## 5. Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) ≥ 1.76 (stable)
- [Python](https://www.python.org/) ≥ 3.10 (for benchmark visualisation only)
- `matplotlib`, `pandas` Python packages (optional, for plots)

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Python plotting dependencies (optional)
pip install matplotlib pandas
```

### Clone & Build

```bash
git clone https://github.com/<org>/project-anamorph.git
cd project-anamorph

# Debug build
cargo build

# Release build (recommended for benchmarks)
cargo build --release
```

### Quick Verify

```bash
# Run all tests
cargo test

# Run with output (verbose)
cargo test -- --nocapture
```

### Access Documentation

```bash
# Build crate docs (includes private crate docs where available)
cargo doc --no-deps

# Open docs in browser (recommended)
cargo doc --no-deps --open

# Alternative: generate rustdoc-only output
cargo rustdoc --no-deps
```

Generated index location:

```text
target/doc/anamorph/index.html
```

---

## 6. Crate Dependencies

All security-critical logic is in Rust. Python is used exclusively for benchmark visualisation.

### Runtime Dependencies

| Crate                                                         | Version | Purpose                                                                                                   | Reference                                 |
| ------------------------------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| [`crypto-bigint`](https://crates.io/crates/crypto-bigint)     | `0.7`   | Constant-width big integers for hardened modular arithmetic                                               | [docs.rs](https://docs.rs/crypto-bigint) |
| [`crypto-primes`](https://crates.io/crates/crypto-primes)     | `0.7`   | Safe-prime generation utilities                                                                           | [docs.rs](https://docs.rs/crypto-primes) |
| [`num-bigint`](https://crates.io/crates/num-bigint)           | `0.4`   | Arbitrary-precision integer operations and random sampling integration                                    | [docs.rs](https://docs.rs/num-bigint)    |
| [`num-traits`](https://crates.io/crates/num-traits)           | `0.2`   | Numeric trait support                                                       | [docs.rs](https://docs.rs/num-traits)    |
| [`num-integer`](https://crates.io/crates/num-integer)         | `0.1`   | Integer helper traits (e.g., parity checks)                                                              | [docs.rs](https://docs.rs/num-integer)   |
| [`rand`](https://crates.io/crates/rand)                       | `0.8`   | Cryptographically secure RNG plumbing for keygen/encryption randomness                                   | [docs.rs](https://docs.rs/rand)          |
| [`getrandom`](https://crates.io/crates/getrandom)             | `0.4`   | OS entropy source access (`sys_rng`)                                                                      | [docs.rs](https://docs.rs/getrandom)     |
| [`hmac`](https://crates.io/crates/hmac)                       | `0.13`  | HMAC-SHA256 MAC generation and verification for anamorphic-CCA hardening                                                  | [docs.rs](https://docs.rs/hmac)          |
| [`sha2`](https://crates.io/crates/sha2)                       | `0.11`  | SHA-256 hash implementation used by the HMAC layer                                                       | [docs.rs](https://docs.rs/sha2)          |
| [`subtle`](https://crates.io/crates/subtle)                   | `2.5`   | Constant-time comparison, conditional selection, and equality across secret-dependent paths              | [docs.rs](https://docs.rs/subtle)        |
| [`block-padding`](https://crates.io/crates/block-padding)     | `0.4`   | PKCS#7 padding utilities                                                              | [docs.rs](https://docs.rs/block-padding) |
| [`zeroize`](https://crates.io/crates/zeroize)                 | `1.7`   | Secure overwrite of private keys, ephemeral exponents, and derived secrets                               | [docs.rs](https://docs.rs/zeroize)       |
| [`argon2`](https://crates.io/crates/argon2)                   | `0.5`   | Memory-hard KDF for deriving anamorphic double-key material                                              | [docs.rs](https://docs.rs/argon2)        |
| [`serde` (optional)](https://crates.io/crates/serde)          | `1`     | Optional serialization support for key/ciphertext transport                                              | [docs.rs](https://docs.rs/serde)         |

### Development Dependencies

| Crate                                             | Version | Purpose                                                                                                                                          |
| ------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`criterion`](https://crates.io/crates/criterion) | `0.5`   | Statistics-driven micro-benchmarking; measures normal vs. anamorphic throughput as covert payload size scales                                    |
| [`proptest`](https://crates.io/crates/proptest)   | `1`     | Property-based testing; verifies that anamorphic ciphertexts are indistinguishable from normal ciphertexts across thousands of randomised inputs |

---

## 7. Usage

> Full API documentation is available via `cargo doc --open`.

### Normal Mode (Secure Packet API)

```rust
use anamorph::normal::{keygen, encrypt, decrypt};

// Key generation
let (pk, sk) = keygen(2048)?;

let mac_key = b"0123456789abcdef";
let block_size = 16;

// Encrypt a plaintext message (PKCS#7 + HMAC packet)
let packet = encrypt(&pk, b"Hello, world!", mac_key, block_size)?;

// Decrypt
let plaintext = decrypt(&sk, &packet, mac_key)?;
assert_eq!(plaintext, b"Hello, world!");
```

### Anamorphic Mode (Secure Packet API)

```rust
use anamorph::anamorphic::{akeygen, aencrypt, adecrypt};
use anamorph::normal::decrypt;

// Key generation — produces a public key and a double key
let (pk, sk, dk) = akeygen(2048)?;

let mac_key = b"0123456789abcdef";
let block_size = 16;

// Encrypt normal message + covert message into an authenticated packet
let packet = aencrypt(
   &pk, &dk,
   b"Normal message", b"Covert payload",
   mac_key, block_size,
)?;

// Normal decryption — adversary sees only the normal message
let normal = decrypt(&sk, &packet, mac_key)?;
assert_eq!(normal, b"Normal message");

// Anamorphic decryption — trusted receiver recovers the covert payload
let decoded = adecrypt(&sk, &dk, &packet, mac_key, b"Covert payload")?;
assert_eq!(decoded.covert_msg, Some(b"Covert payload".to_vec()));
```

Secure packet decryption reveals the visible message across normal and
anamorphic packet domains; covert extraction remains gated on the double key.

Legacy `encrypt`/`decrypt` and `aencrypt`/`adecrypt` are still available for
baseline testing and side-by-side comparisons in the integration tests.

### Coercion Simulation

```rust
use anamorph::normal::decrypt;

// Simulate Type-1 coercion: adversary extracts secret key
// The covert message remains invisible — ciphertext is indistinguishable
let coerced_plaintext = decrypt(&sk, &ciphertext)?;
assert_eq!(coerced_plaintext, b"Normal message"); // adversary sees only this
```

---

## 8. Testing & Benchmarking

### Running Tests

```bash
# All tests
cargo test

# Specific test suite
cargo test --test anamorphic_mode
cargo test --test coercion_simulation
cargo test --test indistinguishability

# With output
cargo test -- --nocapture
```

### Test Coverage

| Suite                  | Description                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| `normal_mode`          | Unit tests for `Gen`, `Enc`, `Dec` including edge cases                                      |
| `anamorphic_mode`      | Integration tests for `aGen`, `aEnc`, `aDec`; both EC22 and EC24                             |
| `coercion_simulation`  | Simulates Type-1 and Type-2 coercion scenarios                                               |
| `indistinguishability` | `proptest` harness; verifies ciphertext indistinguishability over thousands of random inputs |

### Benchmarks

The benchmark suite is split into three independent Criterion groups, each targeting a different operational category:

| Suite | File | Description |
| ----- |------|-------------|
| **Core** | `benches/core.rs` | Main routine benchmarks measuring PRF and XOR anamorphic encryption/decryption across multiple covert payload sizes (1–256 bytes). Includes EC24 extensions (double key ratcheting, covert indicator verification) and normal-mode baselines. Runs in ~minutes. |
| **Slow Setup** | `benches/slow_setup.rs` | Heavyweight one-time operations: safe-prime group parameter generation, full normal key generation (`Gen`), and full anamorphic key generation (`aGen`). Excluded from routine runs due to dominant runtime. |
| **Slow Stream** | `benches/slow_stream.rs` | Stream-mode anamorphic encryption/decryption using rejection sampling. Benchmarks larger covert payloads (1–256 bytes) that are orders of magnitude slower than single-ciphertext modes. Optional extended analysis. |

```bash
# Run all benchmark suites (release mode, required)
cargo bench

# Run a specific suite only
cargo bench --bench core
cargo bench --bench slow_setup
cargo bench --bench slow_stream

# Open HTML report
open target/criterion/report/index.html
```

Benchmarks measure **covert payload size (bytes) vs. anamorphic overhead (µs)**, verifying that overhead scales linearly and quantifying the cost over normal-mode encryption.

```bash
# Generate benchmark plots
python scripts/plot_benchmarks.py target/criterion/
```

### Makefile Targets

```bash
make build       # Debug build
make release     # Release build
make test        # Run full test suite
make bench       # Run Criterion benchmarks
make doc         # Build and open documentation
make clean       # Clean build artefacts
```

---

## 9. Team & Responsibilities

| Member                  | zID      | Responsibilities                                                                                                                                                                                                                          |
| ----------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Gururam Subramanian** | z5636559 | **Core Cryptography** — Full Normal Mode (`Gen`, `Enc`, `Dec`) and Anamorphic Mode (`aGen`, `aEnc`, `aDec`) for both EC22 base scheme and EC24 extension. Owns all group arithmetic and the double-key protocol.                          |
| **Jenny Tien**          | z5265309 | **Formal Analysis & Documentation** — IND-CPA anamorphic security reduction. Formal threat model for Type-1 and Type-2 coercion. EC22 vs. EC24 robustness comparison. Architectural README.                                               |
| **Owen Ouyang**         | z5523864 | **Security Hardening** — Safe prime selection, generator validation, group membership checks, CSPRNG integration, constant-time enforcement via `subtle`, HMAC-SHA256 MAC primitives, block-padding. CCA vulnerability surface analysis. |
| **Matthew Wang**        | z5589818 | **Testing & Benchmarking** — Full test suite for normal and anamorphic modes, edge cases, coercion simulation. Criterion benchmarking scripts. `proptest` indistinguishability harness. Overhead linearity verification.                  |

---

## 10. Project Timeline

### Minimal Deliverable

| Week    | Date (approx.) | Milestone                                                                                                                                                                                                  |
| ------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **W4**  | 24 Mar 2025    | ✅ Submit abstract. Finalise design decisions: safe prime bit-length, block padding size, double-key derivation strategy.                                                                                  |
| **W5**  | 31 Mar 2025    | Initialise GitHub repo with CI. Implement base math utilities: modular exponentiation, safe prime generation, group validation.                                                                            |
| **W6**  | 7 Apr 2025     | 🔍 _Check-in._ Complete Normal Mode (`Gen`, `Enc`, `Dec`). All normal-mode unit tests passing.                                                                                                             |
| **W7**  | 14 Apr 2025    | Implement Anamorphic Mode (`aGen`, `aEnc`, `aDec`) for EC22 base scheme. Begin integration tests.                                                                                                          |
| **W8**  | 21 Apr 2025    | 🔍 _Check-in._ All anamorphic mode tests pass. HMAC helpers and block-padding implemented with dedicated tests.                                                                                           |
| **W9**  | 28 Apr 2025    | Finalise benchmarking: covert payload size vs. overhead curves. Compile complexity analysis. Begin report.                                                                                                 |
| **W10** | 5 May 2025     | Freeze codebase. Finalise README, Makefile, inline docs. Submit report. **Demo:** live coercion simulation showing dictator extracting key, verifying normal message, while covert message remains hidden. |

### Full Deliverable

| Week    | Date (approx.) | Milestone                                                                                                                                                            |
| ------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **W4**  | 24 Mar 2025    | ✅ Submit abstract. Finalise all design decisions including EC24 extension scope and Paillier feasibility.                                                           |
| **W5**  | 31 Mar 2025    | Initialise GitHub repo with CI. Implement base math utilities and Normal Mode (`Gen`, `Enc`, `Dec`).                                                                 |
| **W6**  | 7 Apr 2025     | 🔍 _Check-in._ Complete and test Normal Mode. Begin Anamorphic Mode for EC22 base scheme.                                                                            |
| **W7**  | 14 Apr 2025    | Complete EC22 Anamorphic Mode. Begin EC24 robustness extension: multi-use double keys and covert-message presence indicator.                                         |
| **W8**  | 21 Apr 2025    | 🔍 _Check-in._ Complete EC24 extension with full test coverage. Begin benchmarking normal vs. anamorphic overhead.                                                   |
| **W9**  | 28 Apr 2025    | Finalise benchmarking (Owen + Matthew). Integrate and verify HMAC-SHA256 MAC primitives and block-padding. Compile CCA vulnerability analysis. Begin report.                |
| **W10** | 5 May 2025     | Freeze codebase. Finalise all documentation. Submit report. **Demo:** live two-mode comparison showing EC22 vs. EC24 robustness difference under simulated coercion. |

---

## 11. References

### Primary Papers

1. **Persiano, G., Phan, D. H., & Yung, M. (2022).** _Anamorphic Encryption: Private Communication against a Dictator._
   EUROCRYPT 2022. Lecture Notes in Computer Science, vol. 13276.
   [https://eprint.iacr.org/2022/639](https://eprint.iacr.org/2022/639)

2. **Banfi, F., Gegier, K., Hirt, M., Maurer, U., & Rito, C. (2024).** _Anamorphic Encryption: New Constructions and Homomorphic Realizations._
   EUROCRYPT 2024. Lecture Notes in Computer Science.
   [https://eprint.iacr.org/2023/1666](https://eprint.iacr.org/2023/1666)

### Supporting Literature

3. **ElGamal, T. (1985).** _A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms._
   IEEE Transactions on Information Theory, 31(4), 469–472.
   [https://doi.org/10.1109/TIT.1985.1057074](https://doi.org/10.1109/TIT.1985.1057074)

4. **Kocher, P. (1996).** _Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems._
   CRYPTO 1996. [https://doi.org/10.1007/3-540-68697-5_9](https://doi.org/10.1007/3-540-68697-5_9)

5. **Bernstein, D. J., & Lange, T. (2017).** _Post-quantum cryptography._
   Nature, 549, 188–194. [https://doi.org/10.1038/nature23461](https://doi.org/10.1038/nature23461)
   _(Background context for long-term parameter selection.)_

6. **Biryukov, A., Dinu, D., & Khovratovich, D. (2016).** _Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications._
   IEEE EuroS&P 2016. [https://doi.org/10.1109/EuroSP.2016.31](https://doi.org/10.1109/EuroSP.2016.31)

### Rust Crate Documentation

- [`crypto-bigint`](https://docs.rs/crypto-bigint) — Constant-time big integer arithmetic
- [`subtle`](https://docs.rs/subtle) — Constant-time cryptographic primitives
- [`zeroize`](https://docs.rs/zeroize) — Secure memory zeroing
- [`criterion`](https://docs.rs/criterion) — Statistical benchmarking framework
- [`proptest`](https://docs.rs/proptest) — Property-based testing

---

## Contributing

This is a university research project. For questions or issues, open a GitHub issue or contact a team member directly via UNSW email.

---

_COMP6453 · Applied Cryptography · UNSW Sydney_
