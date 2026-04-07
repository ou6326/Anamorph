//! Coercion simulation tests.
//!
//! Simulates both **Type-1** (receiver key extraction) and **Type-2**
//! (sender forced plaintext) coercion scenarios as defined in the threat
//! model (README §3).
//!
//! In all cases, the covert message must remain indistinguishable from
//! the normal-mode ciphertext even under full key extraction.

use anamorph::anamorphic::{
    akeygen, aencrypt, adecrypt, aencrypt_xor, adecrypt_xor, aencrypt_stream, adecrypt_stream,
};
use anamorph::anamorphic::decrypt::verify_covert_presence;
use anamorph::normal::{encrypt, decrypt};
use num_bigint::BigUint;

// =========================================================================
// Type-1 Coercion: Adversary extracts the receiver's secret key
// =========================================================================

/// Type-1 coercion with PRF-mode anamorphic encryption.
///
/// The adversary extracts `sk` and can decrypt normally, but without
/// the double key `dk`, the covert message remains invisible.
#[test]
fn test_type1_prf_mode() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let normal_msg = b"inn";
    let covert_msg = b"res";

    let ct = aencrypt(&pk, &dk, normal_msg, covert_msg).expect("aencrypt");

    // === Adversary's view (has sk, does NOT have dk) ===
    let adversary_view = decrypt(&sk, &ct).expect("adversary decrypt");
    assert_eq!(adversary_view, normal_msg.to_vec(),
        "adversary should see the normal message");

    // The adversary cannot verify covert presence without dk.
    // Even if they guess a covert message, they can't compute verify_covert_presence
    // without dk.

    // === Legitimate receiver's view (has sk AND dk) ===
    let receiver_view = adecrypt(&sk, &dk, &ct, covert_msg).expect("receiver adecrypt");
    assert_eq!(receiver_view.normal_msg, normal_msg.to_vec());
    assert_eq!(receiver_view.covert_msg, Some(covert_msg.to_vec()),
        "receiver should recover the covert message");
}

/// Type-1 coercion with XOR-mode anamorphic encryption.
///
/// Even with `sk`, the adversary cannot decrypt the covert-encrypted
/// sideband data without `dk`.
#[test]
fn test_type1_xor_mode() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let normal_msg = b"ok";
    let covert_msg = b"coordinates: 51N 0W";

    let (ct, covert_enc) = aencrypt_xor(&pk, &dk, normal_msg, covert_msg)
        .expect("aencrypt_xor");

    // === Adversary's view ===
    let adversary_normal = decrypt(&sk, &ct).expect("adversary decrypt");
    assert_eq!(adversary_normal, normal_msg.to_vec());

    // The adversary sees `covert_enc` but cannot derive the keystream
    // without dk. They would need to solve DLog to get r, then compute
    // dk_pub^r — impossible without dk.

    // Verify that covert_enc is NOT the plaintext covert message
    assert_ne!(&covert_enc, covert_msg,
        "covert_enc should be encrypted, not plaintext");

    // === Legitimate receiver ===
    let receiver_view = adecrypt_xor(&sk, &dk, &ct, &covert_enc)
        .expect("receiver adecrypt_xor");
    assert_eq!(receiver_view.normal_msg, normal_msg.to_vec());
    assert_eq!(receiver_view.covert_msg, Some(covert_msg.to_vec()));
}

/// Type-1 coercion with DH stream mode.
///
/// The adversary sees multiple ciphertexts and decrypts all normally.
/// Each ciphertext contains the same normal message, which looks like
/// normal multi-message communication.
#[test]
fn test_type1_stream_mode() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let normal_msg = b"ok";
    let covert_msg = vec![0x42_u8, 0x00, 0xFF];

    let cts = aencrypt_stream(&pk, &dk, normal_msg, &covert_msg, Some(131072))
        .expect("aencrypt_stream");

    // === Adversary's view ===
    // All ciphertexts decrypt to the normal message.
    for (i, ct) in cts.iter().enumerate() {
        let adversary_normal = decrypt(&sk, ct).expect(&format!("adversary decrypt ct[{i}]"));
        assert_eq!(adversary_normal, normal_msg.to_vec(),
            "adversary should see normal message in ct[{i}]");
    }

    // Without dk, the adversary sees nothing anomalous — just repeated
    // encryptions of the same message (could be normal retransmission).

    // === Legitimate receiver ===
    let receiver_view = adecrypt_stream(&sk, &dk, &cts).expect("receiver adecrypt_stream");
    assert_eq!(receiver_view.normal_msg, normal_msg.to_vec());
    assert_eq!(receiver_view.covert_msg, Some(covert_msg));
}

// =========================================================================
// Type-2 Coercion: Adversary forces the sender to transmit a specific
//                   chosen plaintext (the normal message is dictated).
// =========================================================================

/// Type-2 coercion with PRF-mode anamorphic encryption.
///
/// The adversary dictates the normal message, but the sender can still
/// embed a covert message undetected.
#[test]
fn test_type2_prf_mode() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");

    // Adversary-dictated message
    let dictated_msg = b"ok";
    // Covert message chosen by the sender
    let covert_msg = b"SOS";

    // Sender complies with the dictated message but also embeds covert
    let ct = aencrypt(&pk, &dk, dictated_msg, covert_msg).expect("aencrypt");

    // === Adversary verification ===
    // The adversary decrypts and sees the dictated message
    let adversary_view = decrypt(&sk, &ct).expect("adversary decrypt");
    assert_eq!(adversary_view, dictated_msg.to_vec(),
        "ciphertext must decrypt to the dictated message");

    // The adversary is satisfied — the sender appears to have complied.

    // === Receiver extraction ===
    let receiver_view = adecrypt(&sk, &dk, &ct, covert_msg).expect("adecrypt");
    assert_eq!(receiver_view.normal_msg, dictated_msg.to_vec());
    assert_eq!(receiver_view.covert_msg, Some(covert_msg.to_vec()),
        "covert message is recoverable despite Type-2 coercion");
}

/// Type-2 coercion with XOR-mode.
///
/// The dictated message is the same, but the sender embeds arbitrary
/// covert data in the sideband.
#[test]
fn test_type2_xor_mode() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let dictated_msg = b"ok";
    let covert_msg = b"HELP: agent compromised at location X";

    let (ct, covert_enc) = aencrypt_xor(&pk, &dk, dictated_msg, covert_msg)
        .expect("aencrypt_xor");

    // Adversary sees the dictated message
    let adversary_view = decrypt(&sk, &ct).expect("adversary decrypt");
    assert_eq!(adversary_view, dictated_msg.to_vec());

    // Receiver recovers covert
    let receiver_view = adecrypt_xor(&sk, &dk, &ct, &covert_enc)
        .expect("adecrypt_xor");
    assert_eq!(receiver_view.covert_msg, Some(covert_msg.to_vec()));
}

// =========================================================================
// Cross-mode indistinguishability
// =========================================================================

/// Normal and anamorphic ciphertexts are the same Rust type and have
/// the same structure: `(c1, c2)` with both elements in `[1, p-1]`.
///
/// An adversary with the secret key cannot tell which mode produced
/// a given ciphertext.
#[test]
fn test_cross_mode_indistinguishability() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let msg = b"msg";

    // Normal encryption
    let normal_ct = encrypt(&pk, msg).expect("normal encrypt");

    // PRF anamorphic encryption
    let prf_ct = aencrypt(&pk, &dk, msg, b"cov").expect("prf encrypt");

    // Both decrypt to the same normal message
    let normal_dec = decrypt(&sk, &normal_ct).expect("normal decrypt");
    let prf_dec = decrypt(&sk, &prf_ct).expect("prf decrypt");
    assert_eq!(normal_dec, prf_dec);
    assert_eq!(normal_dec, msg.to_vec());

    // Both have c1, c2 in [1, p-1] — same type, same range
    for ct in [&normal_ct, &prf_ct] {
        assert!(ct.c1 > BigUint::from(0u32) && ct.c1 < pk.params.p);
        assert!(ct.c2 > BigUint::from(0u32) && ct.c2 < pk.params.p);
    }
}

/// The presence check function is sound: it correctly identifies
/// anamorphic ciphertexts and correctly rejects normal ones.
#[test]
fn test_presence_check_soundness() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let covert = b"test";

    // Anamorphic ciphertext — should verify
    let anamorphic_ct = aencrypt(&pk, &dk, b"msg", covert).expect("aencrypt");
    assert!(verify_covert_presence(
        &dk, &anamorphic_ct, covert,
        &pk.params.p, &pk.params.q, &pk.params.g
    ));

    // Normal ciphertext — should NOT verify (overwhelming probability)
    let normal_ct = encrypt(&pk, b"msg").expect("encrypt");
    assert!(!verify_covert_presence(
        &dk, &normal_ct, covert,
        &pk.params.p, &pk.params.q, &pk.params.g
    ));
}

// =========================================================================
// Edge cases
// =========================================================================

/// Multiple anamorphic encryptions with the same dk and covert message
/// produce the same ciphertext (PRF mode is deterministic in r).
#[test]
fn test_prf_determinism() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let ct1 = aencrypt(&pk, &dk, b"msg", b"cov").expect("enc1");
    let ct2 = aencrypt(&pk, &dk, b"msg", b"cov").expect("enc2");
    assert_eq!(ct1, ct2, "PRF mode should be deterministic");
}

/// Different double keys produce different ciphertexts.
#[test]
fn test_different_dk_different_ct() {
    let (pk, _, dk1) = akeygen(64).expect("akeygen1");
    let (_, _, _dk2) = akeygen(64).expect("akeygen2");
    // dk2 won't share the same group params, so we use dk1's params but
    // vary the dk value.
    use crypto_bigint::BoxedUint;
    use num_bigint::RandBigInt;
    use num_traits::One;
    let mut rng = rand::thread_rng();
    let dk2_val = rng.gen_biguint_range(&BigUint::one(), &pk.params.q);
    let dk2 = BoxedUint::from_be_slice_vartime(&dk2_val.to_bytes_be());
    let dk2_pub = pk.params.g.modpow(&dk2_val, &pk.params.p);
    let dk2 = anamorph::anamorphic::DoubleKey { dk: dk2, dk_pub: dk2_pub };

    let ct1 = aencrypt(&pk, &dk1, b"msg", b"cov").expect("enc1");
    let ct2 = aencrypt(&pk, &dk2, b"msg", b"cov").expect("enc2");
    assert_ne!(ct1, ct2, "different dk should produce different ciphertexts");
}
