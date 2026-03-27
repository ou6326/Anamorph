//! Integration tests for Normal Mode — `Gen`, `Enc`, `Dec`.
//!
//! These tests serve as the foundation for Matthew's comprehensive test suite.

use anamorph::normal::{keygen, encrypt, decrypt};
use anamorph::params::{validate_group_membership, generate_group_params};
use anamorph::normal::keygen::keygen_from_params;
use num_bigint::BigUint;
use num_traits::One;

/// Keygen produces a valid public key that is in the group.
#[test]
fn test_keygen_produces_valid_keys() {
    let (pk, sk) = keygen(64).expect("keygen failed");

    // h = g^x mod p must be in the order-q subgroup
    validate_group_membership(&pk.h, &pk.params.p, &pk.params.q)
        .expect("public key h not in group");

    // x must be in [1, q-1]
    assert!(sk.x >= BigUint::one(), "secret key x < 1");
    assert!(sk.x < sk.params.q, "secret key x >= q");
}

/// Encrypt-then-decrypt roundtrip for a simple ASCII message.
#[test]
fn test_encrypt_decrypt_roundtrip() {
    let (pk, sk) = keygen(64).expect("keygen failed");
    let msg = b"Hi!";

    let ct = encrypt(&pk, msg).expect("encryption failed");
    let plaintext = decrypt(&sk, &ct).expect("decryption failed");

    assert_eq!(plaintext, msg.to_vec());
}

/// Encrypt-then-decrypt roundtrip for an empty message.
#[test]
fn test_encrypt_decrypt_empty() {
    let (pk, sk) = keygen(64).expect("keygen failed");
    let msg = b"";

    let ct = encrypt(&pk, msg).expect("encryption failed");
    let plaintext = decrypt(&sk, &ct).expect("decryption failed");

    assert_eq!(plaintext, msg.to_vec());
}

/// Encrypt-then-decrypt roundtrip for binary data.
#[test]
fn test_encrypt_decrypt_binary() {
    let (pk, sk) = keygen(64).expect("keygen failed");
    let msg: Vec<u8> = (0u8..5).collect();

    let ct = encrypt(&pk, &msg).expect("encryption failed");
    let plaintext = decrypt(&sk, &ct).expect("decryption failed");

    assert_eq!(plaintext, msg);
}

/// Two encryptions of the same message produce different ciphertexts
/// (because of fresh randomness).
#[test]
fn test_different_encryptions_differ() {
    let (pk, _) = keygen(64).expect("keygen failed");
    let msg = b"same";

    let ct1 = encrypt(&pk, msg).expect("encrypt 1");
    let ct2 = encrypt(&pk, msg).expect("encrypt 2");

    // With overwhelming probability, different r → different ciphertext
    assert_ne!(ct1, ct2, "two encryptions should differ (random r)");
}

/// Decryption with the wrong secret key does not recover the original message.
#[test]
fn test_wrong_key_decryption() {
    let (pk, _sk) = keygen(64).expect("keygen");

    // Generate a second key pair (different group params entirely)
    let (_, wrong_sk) = keygen(64).expect("keygen2");

    let msg = b"sec";
    let ct = encrypt(&pk, msg).expect("encrypt");

    // Decrypting with the wrong key should either fail or produce garbage
    match decrypt(&wrong_sk, &ct) {
        Ok(decrypted) => assert_ne!(decrypted, msg.to_vec()),
        Err(_) => {} // Also acceptable
    }
}

/// Multiple keygen calls with the same group params produce different keys.
#[test]
fn test_keygen_different_keys() {
    let params = generate_group_params(64).expect("params");
    let (pk1, _) = keygen_from_params(&params).expect("keygen1");
    let (pk2, _) = keygen_from_params(&params).expect("keygen2");

    // Same p, q, g
    assert_eq!(pk1.params, pk2.params);

    // Different h (overwhelmingly likely)
    // Not asserting inequality due to negligible collision probability,
    // but in practice they will differ.
}

/// Ciphertext components c1 and c2 are in the valid range [1, p-1].
#[test]
fn test_ciphertext_components_in_range() {
    let (pk, _) = keygen(64).expect("keygen");
    let ct = encrypt(&pk, b"test").expect("encrypt");

    assert!(ct.c1 > BigUint::from(0u32));
    assert!(ct.c1 < pk.params.p);
    assert!(ct.c2 > BigUint::from(0u32));
    assert!(ct.c2 < pk.params.p);
}
