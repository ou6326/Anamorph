//! Integration tests for the EC24 robustness extensions.
//!
//! Tests the multi-use double-key ratcheting protocol and the
//! covert-message presence indicator.

use anamorph::anamorphic::{
    adecrypt, adecrypt_xor, aencrypt, aencrypt_xor, akeygen,
};
use anamorph::ec24::{verify_covert_indicator, MultiUseDoubleKey};
use anamorph::normal::{decrypt, encrypt};

const TEST_MAC_KEY: &[u8] = b"0123456789abcdef";
const TEST_BLOCK_SIZE: usize = 8;

// =========================================================================
// Multi-Use Double Key (Ratcheting)
// =========================================================================

/// Each ratchet step must produce a different ciphertext for the same
/// covert message, proving that the underlying dk has changed.
#[test]
fn test_ratchet_produces_distinct_ciphertexts() {
    let (pk, _sk, dk) = akeygen(128).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk);

    let ct0 = aencrypt(
        &pk,
        multi_dk.current_key(),
        b"msg",
        b"cov",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
        .expect("enc round 0");

    multi_dk.ratchet(&pk.params);

    let ct1 = aencrypt(
        &pk,
        multi_dk.current_key(),
        b"msg",
        b"cov",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
        .expect("enc round 1");

    // Same normal + covert inputs -> different ciphertext after ratchet.
    assert_ne!(ct0, ct1, "ratcheted key must produce different ciphertext");
}

/// The covert message must be recoverable from every ratchet round
/// when both sender and receiver ratchet in lockstep.
#[test]
fn test_ratchet_roundtrip_lockstep() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let mut sender_dk = MultiUseDoubleKey::new(dk.clone());
    let mut receiver_dk = MultiUseDoubleKey::new(dk);

    for round in 0..5 {
        let covert = format!("covert-{round}");
        let packet = aencrypt(
            &pk,
            sender_dk.current_key(),
            b"normal",
            covert.as_bytes(),
            TEST_MAC_KEY,
            TEST_BLOCK_SIZE,
        )
        .expect("sender encrypt");

        // Both parties verify covert presence
        let present = verify_covert_indicator(
            receiver_dk.current_key(),
            &packet,
            TEST_MAC_KEY,
            covert.as_bytes(),
            &pk.params.p,
            &pk.params.q,
            &pk.params.g,
        )
        .expect("covert indicator");
        assert!(present, "covert should be detectable in round {round}");

        // Receiver recovers both messages
        let result = adecrypt(
            &sk,
            receiver_dk.current_key(),
            &packet,
            TEST_MAC_KEY,
            covert.as_bytes(),
        )
        .expect("receiver decrypt");
        assert_eq!(result.normal_msg, b"normal".to_vec());
        assert_eq!(
            result.covert_msg.as_ref().unwrap(),
            covert.as_bytes(),
            "covert recovery failed in round {round}"
        );

        // Both ratchet forward
        sender_dk.ratchet(&pk.params);
        receiver_dk.ratchet(&pk.params);
    }
}

/// After ratcheting, the OLD key should no longer verify presence
/// for new ciphertexts, preventing replay across epochs.
#[test]
fn test_ratchet_forward_secrecy() {
    let (pk, _sk, dk) = akeygen(128).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk.clone());
    let old_dk = dk; // snapshot of epoch 0

    multi_dk.ratchet(&pk.params);

    let packet = aencrypt(
        &pk,
        multi_dk.current_key(),
        b"msg",
        b"cov",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
        .expect("encrypt with ratcheted key");

    // Old (pre-ratchet) key should NOT verify presence
    let stale_check = verify_covert_indicator(
        &old_dk,
        &packet,
        TEST_MAC_KEY,
        b"cov",
        &pk.params.p,
        &pk.params.q,
        &pk.params.g,
    )
    .expect("stale indicator");
    assert!(
        !stale_check,
        "old dk should not verify ciphertext from ratcheted epoch"
    );

    // Current key SHOULD verify
    let current_check = verify_covert_indicator(
        multi_dk.current_key(),
        &packet,
        TEST_MAC_KEY,
        b"cov",
        &pk.params.p,
        &pk.params.q,
        &pk.params.g,
    )
    .expect("current indicator");
    assert!(current_check, "current dk should verify");
}

/// use_count must advance monotonically with each ratchet.
#[test]
fn test_ratchet_use_count() {
    let (pk, _, dk) = akeygen(128).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk);
    assert_eq!(multi_dk.use_count, 0);

    for expected in 1..=10 {
        multi_dk.ratchet(&pk.params);
        assert_eq!(multi_dk.use_count, expected);
    }
}

// =========================================================================
// Multi-Use Double Key with XOR Mode
// =========================================================================

/// XOR mode should also work across ratchet rounds.
#[test]
fn test_ratchet_xor_mode() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let mut sender_dk = MultiUseDoubleKey::new(dk.clone());
    let mut receiver_dk = MultiUseDoubleKey::new(dk);

    for round in 0..3 {
        let covert = format!("xor-covert-{round}");
        let packet = aencrypt_xor(
            &pk,
            sender_dk.current_key(),
            b"normal",
            covert.as_bytes(),
            TEST_MAC_KEY,
            TEST_BLOCK_SIZE,
        )
        .expect("XOR encrypt");

        let result = adecrypt_xor(
            &sk,
            receiver_dk.current_key(),
            &packet,
            TEST_MAC_KEY,
        )
            .expect("XOR decrypt");
        assert_eq!(result.normal_msg, b"normal".to_vec());
        assert_eq!(
            result.covert_msg.as_ref().unwrap(),
            covert.as_bytes(),
            "XOR covert recovery failed in round {round}"
        );

        sender_dk.ratchet(&pk.params);
        receiver_dk.ratchet(&pk.params);
    }
}

// =========================================================================
// Presence Indicator
// =========================================================================

/// verify_covert_presence must return true for anamorphic ciphertexts
/// with the correct candidate, and false for wrong candidates.
#[test]
fn test_presence_indicator_correct_candidate() {
    let (pk, _, dk) = akeygen(128).expect("akeygen");
    let packet = aencrypt(
        &pk,
        &dk,
        b"hello",
        b"secret",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
    .expect("aencrypt");

    assert!(verify_covert_indicator(
        &dk,
        &packet,
        TEST_MAC_KEY,
        b"secret",
        &pk.params.p, &pk.params.q, &pk.params.g,
    )
    .expect("indicator true"));
    assert!(!verify_covert_indicator(
        &dk,
        &packet,
        TEST_MAC_KEY,
        b"wrong",
        &pk.params.p, &pk.params.q, &pk.params.g,
    )
    .expect("indicator false"));
}

/// verify_covert_presence must return false for a normal (non-anamorphic)
/// ciphertext, even when given the correct dk.
#[test]
fn test_presence_indicator_normal_ct() {
    let (pk, _, dk) = akeygen(128).expect("akeygen");
    let packet = encrypt(&pk, b"hello", TEST_MAC_KEY, TEST_BLOCK_SIZE).expect("normal encrypt");

    // No covert payload was embedded, so any candidate should fail.
    assert!(verify_covert_indicator(
        &dk,
        &packet,
        TEST_MAC_KEY,
        b"anything",
        &pk.params.p, &pk.params.q, &pk.params.g,
    )
    .expect("indicator on normal packet should return false")
        == false);
}

/// Secure packet visible decryption should work across normal and anamorphic packets.
#[test]
fn test_ec24_indistinguishability() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk);

    let normal_packet = encrypt(&pk, b"msg", TEST_MAC_KEY, TEST_BLOCK_SIZE).expect("normal encrypt");

    multi_dk.ratchet(&pk.params);
    let ec24_packet = aencrypt(
        &pk,
        multi_dk.current_key(),
        b"msg",
        b"hidden",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
        .expect("ec24 encrypt");

    let n_dec = decrypt(&sk, &normal_packet, TEST_MAC_KEY).expect("normal decrypt");
    let a_dec = decrypt(&sk, &ec24_packet, TEST_MAC_KEY).expect("anamorphic visible decrypt");

    assert_eq!(a_dec, b"msg".to_vec());
    assert_eq!(n_dec, b"msg".to_vec());
}

// =========================================================================
// Type-1 Coercion with EC24 Multi-Use Key
// =========================================================================

/// Under Type-1 coercion with a ratcheted key, the adversary still
/// sees only the normal plaintext.
#[test]
fn test_type1_coercion_ec24_ratcheted() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk);

    // Ratchet a few times
    multi_dk.ratchet(&pk.params);
    multi_dk.ratchet(&pk.params);

    let packet = aencrypt(
        &pk,
        multi_dk.current_key(),
        b"safe",
        b"HELP",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
        .expect("encrypt");

    // Adversary with sk only
    let adversary = decrypt(&sk, &packet, TEST_MAC_KEY).expect("visible decrypt");
    assert_eq!(adversary, b"safe".to_vec());

    // Receiver with same ratchet state
    let receiver = adecrypt(
        &sk,
        multi_dk.current_key(),
        &packet,
        TEST_MAC_KEY,
        b"HELP",
    )
        .expect("receiver decrypt");
    assert_eq!(receiver.normal_msg, b"safe".to_vec());
    assert_eq!(receiver.covert_msg, Some(b"HELP".to_vec()));
}
