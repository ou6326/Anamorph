//! Behavioral comparison tests between legacy and secure packet APIs.
//!
//! These tests keep old interfaces available for baseline comparison while
//! validating the migrated secure defaults (padding + MAC + packet domains).

use anamorph::anamorphic::{
    adecrypt_legacy,
    adecrypt,
    adecrypt_stream_legacy,
    adecrypt_stream,
    adecrypt_xor_legacy,
    adecrypt_xor,
    aencrypt_legacy,
    aencrypt,
    aencrypt_stream_legacy,
    aencrypt_stream,
    aencrypt_xor_legacy,
    aencrypt_xor,
    akeygen,
};
use anamorph::normal::{
    decrypt,
    decrypt_legacy,
    encrypt,
    encrypt_legacy,
};
use anamorph::errors::AnamorphError;

const TEST_MAC_KEY: &[u8] = b"0123456789abcdef";
const TEST_BLOCK_SIZE: usize = 8;

#[test]
fn test_normal_legacy_vs_secure_plaintext_equivalence() {
    let (pk, sk) = anamorph::normal::keygen(128).expect("keygen");
    let msg = b"cmp";

    let legacy_ct = encrypt_legacy(&pk, msg).expect("legacy encrypt");
    let legacy_pt = decrypt_legacy(&sk, &legacy_ct).expect("legacy decrypt");

    let secure_packet = encrypt(&pk, msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encrypt");
    let secure_pt = decrypt(&sk, &secure_packet, TEST_MAC_KEY)
        .expect("secure decrypt");

    assert_eq!(legacy_pt, msg.to_vec());
    assert_eq!(secure_pt, msg.to_vec());
    assert_eq!(legacy_pt, secure_pt);
}

#[test]
fn test_prf_legacy_vs_secure_behavior() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let normal = b"cmp-prf";
    let covert = b"cov";

    let legacy_ct = aencrypt_legacy(&pk, &dk, normal, covert).expect("legacy aencrypt");
    let legacy_normal = decrypt_legacy(&sk, &legacy_ct).expect("legacy normal decrypt");
    let legacy_full = adecrypt_legacy(&sk, &dk, &legacy_ct, covert).expect("legacy adecrypt");

    let secure_packet = aencrypt(
        &pk, &dk,
        normal, covert,
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
    .expect("secure aencrypt");
    let secure_full = adecrypt(&sk, &dk, &secure_packet, TEST_MAC_KEY, covert)
        .expect("secure adecrypt");

    assert_eq!(legacy_normal, normal.to_vec());
    assert_eq!(legacy_full.normal_msg, normal.to_vec());
    assert_eq!(legacy_full.covert_msg, Some(covert.to_vec()));
    assert_eq!(secure_full.normal_msg, legacy_full.normal_msg);
    assert_eq!(secure_full.covert_msg, legacy_full.covert_msg);
}

#[test]
fn test_stream_and_xor_legacy_vs_secure_behavior() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");

    let stream_covert = vec![0x11_u8, 0x42_u8];
    let legacy_stream = aencrypt_stream_legacy(&pk, &dk, b"cmp", &stream_covert, Some(131072))
        .expect("legacy stream encrypt");
    let legacy_stream_pt = adecrypt_stream_legacy(&sk, &dk, &legacy_stream).expect("legacy stream decrypt");

    let secure_stream = aencrypt_stream(
        &pk, &dk,
        b"cmp", &stream_covert,
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
        Some(131072),
    )
    .expect("secure stream encrypt");
    let secure_stream_pt =
        adecrypt_stream(&sk, &dk, &secure_stream, TEST_MAC_KEY)
            .expect("secure stream decrypt");

    assert_eq!(legacy_stream_pt.normal_msg, b"cmp".to_vec());
    assert_eq!(legacy_stream_pt.covert_msg, Some(stream_covert.clone()));
    assert_eq!(secure_stream_pt.normal_msg, legacy_stream_pt.normal_msg);
    assert_eq!(secure_stream_pt.covert_msg, legacy_stream_pt.covert_msg);

    let xor_covert = b"xor-covert";
    let (legacy_xor_ct, legacy_xor_enc) = aencrypt_xor_legacy(&pk, &dk, b"cmp", xor_covert)
        .expect("legacy xor encrypt");
    let legacy_xor_pt = adecrypt_xor_legacy(&sk, &dk, &legacy_xor_ct, &legacy_xor_enc)
        .expect("legacy xor decrypt");

    let secure_xor_packet = aencrypt_xor(
        &pk, &dk,
        b"cmp", xor_covert,
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
    .expect("secure xor encrypt");
    let secure_xor_pt = adecrypt_xor(&sk, &dk, &secure_xor_packet, TEST_MAC_KEY)
        .expect("secure xor decrypt");

    assert_eq!(legacy_xor_pt.normal_msg, b"cmp".to_vec());
    assert_eq!(legacy_xor_pt.covert_msg, Some(xor_covert.to_vec()));
    assert_eq!(secure_xor_pt.normal_msg, legacy_xor_pt.normal_msg);
    assert_eq!(secure_xor_pt.covert_msg, legacy_xor_pt.covert_msg);
}

#[test]
fn test_secure_packet_visible_view_matches_legacy_ciphertext() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");

    let legacy_ct = aencrypt_legacy(&pk, &dk, b"cmp", b"cov").expect("legacy aencrypt");
    let legacy_normal = decrypt_legacy(&sk, &legacy_ct).expect("legacy decrypt");
    assert_eq!(legacy_normal, b"cmp".to_vec());

    let secure_anamorphic_packet = aencrypt(
        &pk, &dk,
        b"cmp", b"cov",
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
    .expect("secure aencrypt");

    let normal_view = decrypt(&sk, &secure_anamorphic_packet, TEST_MAC_KEY)
        .expect("visible secure decrypt");
    assert_eq!(normal_view, b"cmp".to_vec());
}

#[test]
fn test_tampering_legacy_vs_secure_normal_path() {
    let (pk, sk) = anamorph::normal::keygen(128).expect("keygen");
    let msg = b"cmp";

    let mut legacy_ct = encrypt_legacy(&pk, msg).expect("legacy encrypt");
    legacy_ct.c2 = (&legacy_ct.c2 + 1u32) % &pk.params.p;

    // Legacy path has no integrity envelope: tampering may yield decode error or garbage plaintext.
    let legacy_result = decrypt_legacy(&sk, &legacy_ct);
    match legacy_result {
        Ok(pt) => assert_ne!(pt, msg.to_vec(), "tampered legacy ciphertext should not recover original plaintext"),
        Err(_) => {}
    }

    let mut secure_packet = encrypt(&pk, msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encrypt");
    let last = secure_packet.len() - 1;
    secure_packet[last] ^= 0x01;

    let secure_result = decrypt(&sk, &secure_packet, TEST_MAC_KEY);
    assert!(matches!(secure_result, Err(AnamorphError::IntegrityError)));
}

#[test]
fn test_tampering_legacy_vs_secure_anamorphic_prf_path() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let normal = b"cmp";
    let covert = b"cov";

    let mut legacy_ct = aencrypt_legacy(&pk, &dk, normal, covert).expect("legacy aencrypt");
    legacy_ct.c1 = (&legacy_ct.c1 + 1u32) % &pk.params.p;

    // Legacy PRF path may fail or return a non-matching covert candidate after tampering.
    let legacy_result = adecrypt_legacy(&sk, &dk, &legacy_ct, covert);
    match legacy_result {
        Ok(pt) => assert_ne!(pt.covert_msg, Some(covert.to_vec())),
        Err(_) => {}
    }

    let mut secure_packet = aencrypt(
        &pk, &dk, normal, covert,
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
    .expect("secure aencrypt");
    let last = secure_packet.len() - 1;
    secure_packet[last] ^= 0x01;

    let secure_result = adecrypt(&sk, &dk, &secure_packet, TEST_MAC_KEY, covert);
    assert!(matches!(secure_result, Err(AnamorphError::IntegrityError)));
}
