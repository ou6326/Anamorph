//! Integration tests for Anamorphic Mode (EC22 base scheme).
//!
//! Tests cover all three encryption modes (PRF, DH stream, DH XOR) and
//! verify correctness, indistinguishability, and coercion resistance.

use anamorph::anamorphic::{akeygen, aencrypt, adecrypt, aencrypt_stream, adecrypt_stream, aencrypt_xor, adecrypt_xor};
use anamorph::anamorphic::decrypt::{adecrypt_search, verify_covert_presence};
use anamorph::normal::{encrypt, decrypt};
use num_bigint::BigUint;

// =========================================================================
// aGen tests
// =========================================================================

/// aGen produces valid keys, double key, and DH public value.
#[test]
fn test_akeygen_produces_double_key() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");

    // Public key in group
    anamorph::params::validate_group_membership(&pk.h, &pk.params.p, &pk.params.q)
        .expect("pk.h in group");

    // Double key exponent in valid range
    let dk_value = BigUint::from_bytes_be(&dk.dk.to_be_bytes());
    assert!(dk_value >= BigUint::from(1u32));
    assert!(dk_value < pk.params.q);

    // dk_pub = g^dk mod p
    let expected_dk_pub = anamorph::ct::ct_modpow_boxed(&pk.params.g, &dk.dk, &pk.params.p)
        .expect("dk_pub");
    assert_eq!(dk.dk_pub, expected_dk_pub);

    // Keys share the same group params
    assert_eq!(pk.params, sk.params);
}

/// DH shared secret is consistent between sender and receiver.
#[test]
fn test_dh_shared_secret() {
    use num_bigint::RandBigInt;
    use num_traits::One;

    let (pk, _, dk) = akeygen(64).expect("akeygen");

    let mut rng = rand::thread_rng();
    let r = rng.gen_biguint_range(&BigUint::one(), &pk.params.q);

    // Sender: dk_pub^r mod p
    let sender_shared = dk.dk_pub.modpow(&r, &pk.params.p);

    // Receiver: c1^dk mod p (where c1 = g^r)
    let c1 = pk.params.g.modpow(&r, &pk.params.p);
    let receiver_shared = dk.shared_secret(&c1, &pk.params.p);

    assert_eq!(sender_shared, receiver_shared);
}

// =========================================================================
// PRF mode tests
// =========================================================================

/// PRF aEnc → normal Dec recovers the normal message.
#[test]
fn test_prf_aencrypt_normal_decrypt() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt(&pk, &dk, b"pub", b"hid").expect("aencrypt");
    let decrypted = decrypt(&sk, &ct).expect("decrypt");
    assert_eq!(decrypted, b"pub".to_vec());
}

/// PRF aEnc → aDec successfully verifies the covert message.
#[test]
fn test_prf_aencrypt_covert_verification() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt(&pk, &dk, b"hello", b"secret").expect("aencrypt");

    let result = adecrypt(&sk, &dk, &ct, b"secret").expect("adecrypt");
    assert_eq!(result.normal_msg, b"hello".to_vec());
    assert_eq!(result.covert_msg, Some(b"secret".to_vec()));
}

/// PRF aDec with wrong candidate returns None for covert.
#[test]
fn test_prf_wrong_candidate() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt(&pk, &dk, b"norm", b"real").expect("aencrypt");

    let result = adecrypt(&sk, &dk, &ct, b"fake").expect("adecrypt");
    assert_eq!(result.normal_msg, b"norm".to_vec());
    assert_eq!(result.covert_msg, None);
}

/// PRF brute-force search finds the covert message.
#[test]
fn test_prf_search() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt(&pk, &dk, b"hay", b"nd").expect("aencrypt");

    let candidates: Vec<Vec<u8>> = vec![
        b"w1".to_vec(), b"w2".to_vec(), b"nd".to_vec(), b"w3".to_vec(),
    ];
    let result = adecrypt_search(&sk, &dk, &ct, &candidates).expect("search");
    assert_eq!(result.covert_msg, Some(b"nd".to_vec()));
}

/// verify_covert_presence correctly identifies covert messages.
#[test]
fn test_verify_covert_presence_function() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt(&pk, &dk, b"norm", b"cov").expect("aencrypt");

    assert!(verify_covert_presence(
        &dk, &ct, b"cov", &pk.params.p, &pk.params.q, &pk.params.g
    ));
    assert!(!verify_covert_presence(
        &dk, &ct, b"wrong", &pk.params.p, &pk.params.q, &pk.params.g
    ));
}

// =========================================================================
// DH stream mode tests
// =========================================================================

/// DH stream mode: roundtrip for a single covert byte.
#[test]
fn test_stream_single_byte_roundtrip() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let covert = vec![0x42_u8];
    let cts = aencrypt_stream(&pk, &dk, b"hi", &covert, Some(131072))
        .expect("aencrypt_stream");
    assert_eq!(cts.len(), 1);

    let result = adecrypt_stream(&sk, &dk, &cts).expect("adecrypt_stream");
    assert_eq!(result.normal_msg, b"hi".to_vec());
    assert_eq!(result.covert_msg, Some(covert));
}

/// DH stream mode: all ciphertexts decrypt to the same normal message.
#[test]
fn test_stream_all_cts_same_normal() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let cts = aencrypt_stream(&pk, &dk, b"hi", &[0x00], Some(131072))
        .expect("aencrypt_stream");

    for ct in &cts {
        let decrypted = decrypt(&sk, ct).expect("decrypt");
        assert_eq!(decrypted, b"hi".to_vec());
    }
}

/// DH stream mode: empty covert message produces empty vector.
#[test]
fn test_stream_empty_covert() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let cts = aencrypt_stream(&pk, &dk, b"hi", &[], None)
        .expect("aencrypt_stream");
    assert!(cts.is_empty());

    let result = adecrypt_stream(&sk, &dk, &cts).expect("adecrypt_stream");
    assert_eq!(result.covert_msg, Some(Vec::new()));
}

// =========================================================================
// DH XOR mode tests
// =========================================================================

/// DH XOR mode: full roundtrip with arbitrary-length covert message.
#[test]
fn test_xor_roundtrip() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let covert_msg = b"arbitrary length covert message!";

    let (ct, covert_enc) = aencrypt_xor(&pk, &dk, b"hi", covert_msg)
        .expect("aencrypt_xor");

    let result = adecrypt_xor(&sk, &dk, &ct, &covert_enc)
        .expect("adecrypt_xor");

    assert_eq!(result.normal_msg, b"hi".to_vec());
    assert_eq!(result.covert_msg, Some(covert_msg.to_vec()));
}

/// DH XOR mode: normal decryption ignores covert data.
#[test]
fn test_xor_normal_decrypt_unaffected() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let (ct, _) = aencrypt_xor(&pk, &dk, b"hi", b"hidden stuff")
        .expect("aencrypt_xor");

    let decrypted = decrypt(&sk, &ct).expect("decrypt");
    assert_eq!(decrypted, b"hi".to_vec());
}

/// DH XOR mode: different covert messages produce different encrypted blobs.
#[test]
fn test_xor_different_coverts() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let (_, enc1) = aencrypt_xor(&pk, &dk, b"hi", b"aaa").expect("xor1");
    let (_, enc2) = aencrypt_xor(&pk, &dk, b"hi", b"bbb").expect("xor2");
    // Encrypted covert blobs differ (different source messages)
    assert_ne!(enc1, enc2);
}

/// DH XOR mode: empty covert message.
#[test]
fn test_xor_empty_covert() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let (ct, enc) = aencrypt_xor(&pk, &dk, b"hi", b"").expect("xor");
    let result = adecrypt_xor(&sk, &dk, &ct, &enc).expect("xor decrypt");
    assert_eq!(result.covert_msg, Some(Vec::new()));
}

// =========================================================================
// Indistinguishability
// =========================================================================

/// Anamorphic ciphertexts are structurally identical to normal ciphertexts.
#[test]
fn test_ciphertext_format_matches_normal() {
    let (pk, _sk, dk) = akeygen(64).expect("akeygen");

    let normal_ct = encrypt(&pk, b"msg").expect("normal encrypt");
    let anamorphic_ct = aencrypt(&pk, &dk, b"msg", b"cov").expect("anamorphic encrypt");

    // Both c1 and c2 in [1, p-1] — same type, same range
    assert!(anamorphic_ct.c1 > BigUint::from(0u32));
    assert!(anamorphic_ct.c1 < pk.params.p);
    assert!(anamorphic_ct.c2 > BigUint::from(0u32));
    assert!(anamorphic_ct.c2 < pk.params.p);

    assert!(normal_ct.c1 > BigUint::from(0u32));
    assert!(normal_ct.c1 < pk.params.p);
}
