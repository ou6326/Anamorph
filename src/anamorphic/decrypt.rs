//! Anamorphic decryption — `aDec(sk, dk, c)`.
//!
//! Recovers **both** the normal message and the covert message from an
//! anamorphic ciphertext.  Provides three extraction methods matching
//! the three encryption modes:
//!
//! | Method | Encryption mode | Extraction |
//! |--------|----------------|------------|
//! | [`adecrypt`] | `aencrypt` (PRF) | Candidate verification |
//! | [`adecrypt_search`] | `aencrypt` (PRF) | Brute-force over candidates |
//! | [`adecrypt_stream`] | `aencrypt_stream` | Direct (DH shared secret) |
//! | [`adecrypt_xor`] | `aencrypt_xor` | Direct (DH + XOR) |

use num_bigint::BigUint;

use crate::errors::Result;
use crate::normal::decrypt::decrypt;
use crate::normal::encrypt::Ciphertext;
use crate::normal::keygen::SecretKey;
use super::encrypt::{derive_keystream, derive_randomness, shared_to_byte};
use super::keygen::DoubleKey;

/// Result of anamorphic decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnamorphicPlaintext {
    /// The normal (visible) message.
    pub normal_msg: Vec<u8>,
    /// The covert (hidden) message, if recovered.
    pub covert_msg: Option<Vec<u8>>,
}

// =========================================================================
// 1. PRF-Based decryption (candidate verification)
// =========================================================================

/// Anamorphic decryption with candidate verification (PRF mode).
///
/// Recovers the normal message via standard decryption, then verifies
/// whether the given `candidate_covert` was embedded as the covert message
/// by checking `g^{H(dk, candidate)} ≡ c1 (mod p)`.
///
/// Returns `AnamorphicPlaintext` with `covert_msg = Some(...)` if the
/// candidate matches, or `None` otherwise.
pub fn adecrypt(
    sk: &SecretKey,
    dk: &DoubleKey,
    ct: &Ciphertext,
    candidate_covert: &[u8],
) -> Result<AnamorphicPlaintext> {
    let normal_msg = decrypt(sk, ct)?;

    let r = derive_randomness(dk, candidate_covert, &sk.params.q);
    let expected_c1 = sk.params.g.modpow(&r, &sk.params.p);

    let covert_msg = if expected_c1 == ct.c1 {
        Some(candidate_covert.to_vec())
    } else {
        None
    };

    Ok(AnamorphicPlaintext {
        normal_msg,
        covert_msg,
    })
}

/// Anamorphic decryption with brute-force search over a candidate set (PRF mode).
///
/// Searches through `candidates` and returns the first match whose
/// derived randomness produces `c1`.
pub fn adecrypt_search(
    sk: &SecretKey,
    dk: &DoubleKey,
    ct: &Ciphertext,
    candidates: &[Vec<u8>],
) -> Result<AnamorphicPlaintext> {
    let normal_msg = decrypt(sk, ct)?;

    for candidate in candidates {
        let r = derive_randomness(dk, candidate, &sk.params.q);
        let expected_c1 = sk.params.g.modpow(&r, &sk.params.p);

        if expected_c1 == ct.c1 {
            return Ok(AnamorphicPlaintext {
                normal_msg,
                covert_msg: Some(candidate.clone()),
            });
        }
    }

    Ok(AnamorphicPlaintext {
        normal_msg,
        covert_msg: None,
    })
}

// =========================================================================
// 2. DH-Based direct extraction (multi-ciphertext, rejection sampling)
// =========================================================================

/// Anamorphic decryption for the multi-ciphertext DH stream mode.
///
/// Extracts one covert byte from each ciphertext by computing the DH
/// shared secret `c1^dk mod p` and taking `SHA-256(shared)[0]`.
///
/// The normal message is decrypted from the **first** ciphertext
/// (all ciphertexts encrypt the same normal message).
///
/// # Arguments
///
/// - `sk` — receiver's secret key
/// - `dk` — shared double key
/// - `cts` — vector of ciphertexts (one per covert byte)
///
/// # Returns
///
/// `AnamorphicPlaintext` with the normal message and the reassembled
/// covert message.
pub fn adecrypt_stream(
    sk: &SecretKey,
    dk: &DoubleKey,
    cts: &[Ciphertext],
) -> Result<AnamorphicPlaintext> {
    if cts.is_empty() {
        let normal_msg = Vec::new();
        return Ok(AnamorphicPlaintext {
            normal_msg,
            covert_msg: Some(Vec::new()),
        });
    }

    // Decrypt normal message from the first ciphertext.
    let normal_msg = decrypt(sk, &cts[0])?;

    // Extract one covert byte per ciphertext.
    let mut covert_bytes = Vec::with_capacity(cts.len());
    for ct in cts {
        let shared = dk.shared_secret(&ct.c1, &sk.params.p);
        let covert_byte = shared_to_byte(&shared);
        covert_bytes.push(covert_byte);
    }

    Ok(AnamorphicPlaintext {
        normal_msg,
        covert_msg: Some(covert_bytes),
    })
}

// =========================================================================
// 3. DH-XOR decryption (fast, single ciphertext + sideband)
// =========================================================================

/// Anamorphic decryption for the XOR-based DH mode.
///
/// Recovers the covert message from `(ciphertext, covert_encrypted)` by:
/// 1. Computing the DH shared secret `c1^dk mod p`.
/// 2. Deriving the keystream `SHA-256(shared || counter)`.
/// 3. XORing `covert_encrypted` with the keystream.
///
/// # Arguments
///
/// - `sk` — receiver's secret key
/// - `dk` — shared double key
/// - `ct` — the ciphertext
/// - `covert_encrypted` — the XOR-encrypted covert bytes (transmitted alongside `ct`)
pub fn adecrypt_xor(
    sk: &SecretKey,
    dk: &DoubleKey,
    ct: &Ciphertext,
    covert_encrypted: &[u8],
) -> Result<AnamorphicPlaintext> {
    let normal_msg = decrypt(sk, ct)?;

    // Compute shared secret: c1^dk mod p
    let shared = dk.shared_secret(&ct.c1, &sk.params.p);

    // Derive keystream and XOR to recover covert message
    let keystream = derive_keystream(&shared, covert_encrypted.len());
    let covert_msg: Vec<u8> = covert_encrypted
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect();

    Ok(AnamorphicPlaintext {
        normal_msg,
        covert_msg: Some(covert_msg),
    })
}

// =========================================================================
// Presence check
// =========================================================================

/// Check if a ciphertext carries a specific covert message (PRF mode)
/// without performing full decryption.
///
/// Fast verification: checks `g^{H(dk, m')} ≡ c1 (mod p)`.
pub fn verify_covert_presence(
    dk: &DoubleKey,
    ct: &Ciphertext,
    candidate_covert: &[u8],
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> bool {
    let r = derive_randomness(dk, candidate_covert, q);
    let expected_c1 = g.modpow(&r, p);
    expected_c1 == ct.c1
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anamorphic::encrypt::{aencrypt, aencrypt_stream, aencrypt_xor};
    use crate::anamorphic::keygen::akeygen;

    // ----- PRF mode tests -----

    #[test]
    fn test_adecrypt_recovers_both_messages() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        let ct = aencrypt(&pk, &dk, b"vis", b"hid").expect("aencrypt");
        let result = adecrypt(&sk, &dk, &ct, b"hid").expect("adecrypt");
        assert_eq!(result.normal_msg, b"vis".to_vec());
        assert_eq!(result.covert_msg, Some(b"hid".to_vec()));
    }

    #[test]
    fn test_adecrypt_wrong_candidate_returns_none() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        let ct = aencrypt(&pk, &dk, b"norm", b"sec").expect("aencrypt");
        let result = adecrypt(&sk, &dk, &ct, b"wrong").expect("adecrypt");
        assert_eq!(result.normal_msg, b"norm".to_vec());
        assert_eq!(result.covert_msg, None);
    }

    #[test]
    fn test_adecrypt_search_finds_covert() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        let ct = aencrypt(&pk, &dk, b"hi", b"tgt").expect("aencrypt");
        let candidates: Vec<Vec<u8>> = vec![
            b"w1".to_vec(),
            b"w2".to_vec(),
            b"tgt".to_vec(),
            b"w3".to_vec(),
        ];
        let result = adecrypt_search(&sk, &dk, &ct, &candidates).expect("search");
        assert_eq!(result.covert_msg, Some(b"tgt".to_vec()));
    }

    // ----- DH stream mode tests -----

    #[test]
    fn test_stream_roundtrip_single_byte() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        let covert = vec![0x42_u8];
        let cts = aencrypt_stream(&pk, &dk, b"hi", &covert, Some(131072))
            .expect("aencrypt_stream");
        assert_eq!(cts.len(), 1);

        let result = adecrypt_stream(&sk, &dk, &cts).expect("adecrypt_stream");
        assert_eq!(result.normal_msg, b"hi".to_vec());
        assert_eq!(result.covert_msg, Some(covert));
    }

    #[test]
    fn test_stream_roundtrip_multi_byte() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        // Use bytes that are not too rare in SHA-256 output
        let covert = vec![0x00_u8, 0xFF, 0x42];
        let cts = aencrypt_stream(&pk, &dk, b"hi", &covert, Some(131072))
            .expect("aencrypt_stream");
        assert_eq!(cts.len(), 3);

        let result = adecrypt_stream(&sk, &dk, &cts).expect("adecrypt_stream");
        assert_eq!(result.covert_msg, Some(covert));
    }

    #[test]
    fn test_stream_normal_decrypt_on_each_ct() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        let cts = aencrypt_stream(&pk, &dk, b"hi", &[0x00], Some(131072))
            .expect("aencrypt_stream");

        // Every ciphertext should decrypt to the same normal message
        for ct in &cts {
            let decrypted = crate::normal::decrypt::decrypt(&sk, ct)
                .expect("normal decrypt");
            assert_eq!(decrypted, b"hi".to_vec());
        }
    }

    // ----- XOR mode tests -----

    #[test]
    fn test_xor_roundtrip() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        let covert_msg = b"long covert msg!";

        let (ct, covert_enc) = aencrypt_xor(&pk, &dk, b"hi", covert_msg)
            .expect("aencrypt_xor");

        let result = adecrypt_xor(&sk, &dk, &ct, &covert_enc)
            .expect("adecrypt_xor");

        assert_eq!(result.normal_msg, b"hi".to_vec());
        assert_eq!(result.covert_msg, Some(covert_msg.to_vec()));
    }

    #[test]
    fn test_xor_empty_covert() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");

        let (ct, covert_enc) = aencrypt_xor(&pk, &dk, b"hi", b"")
            .expect("aencrypt_xor");

        let result = adecrypt_xor(&sk, &dk, &ct, &covert_enc)
            .expect("adecrypt_xor");

        assert_eq!(result.covert_msg, Some(Vec::new()));
    }

    // ----- Presence check tests -----

    #[test]
    fn test_verify_covert_presence() {
        let (pk, _, dk) = akeygen(64).expect("akeygen");
        let ct = aencrypt(&pk, &dk, b"norm", b"hid").expect("aencrypt");

        assert!(verify_covert_presence(
            &dk, &ct, b"hid",
            &pk.params.p, &pk.params.q, &pk.params.g
        ));
        assert!(!verify_covert_presence(
            &dk, &ct, b"wrong",
            &pk.params.p, &pk.params.q, &pk.params.g
        ));
    }
}
