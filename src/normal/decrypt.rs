//! ElGamal decryption — `Dec(sk, c)`.
//!
//! Recovers the plaintext bytes from an ElGamal ciphertext using the
//! secret key.

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::ct::ct_modpow_boxed;
use crate::errors::{AnamorphError, Result};
use crate::hardening::{verify_mac, MAC_SIZE};
use crate::padding::unpad_pkcs7;
use super::encrypt::{decode_message, Ciphertext};
use super::keygen::SecretKey;

pub(crate) fn verify_and_extract_packet_body<'a>(
    packet: &'a [u8],
    mac_key: &[u8],
    expected_domain: u8,
) -> Result<&'a [u8]> {
    let min_len = 2 + MAC_SIZE;
    if packet.len() < min_len {
        return Err(AnamorphError::DecryptionFailed(
            "packet too short".into(),
        ));
    }

    if packet[0] != super::encrypt::SECURE_PACKET_VERSION {
        return Err(AnamorphError::DecryptionFailed(
            "unsupported secure packet version".into(),
        ));
    }

    let body_with_tag = &packet[1..];
    let body_len = body_with_tag
        .len()
        .checked_sub(MAC_SIZE)
        .ok_or_else(|| AnamorphError::DecryptionFailed("packet missing tag".into()))?;

    let (body, tag_bytes) = body_with_tag.split_at(body_len);
    if body.first().copied() != Some(expected_domain) {
        return Err(AnamorphError::DecryptionFailed(
            "unexpected secure packet domain".into(),
        ));
    }

    verify_mac(mac_key, body, tag_bytes)?;
    Ok(body)
}

/// Standard ElGamal decryption.
///
/// Given secret key `sk = (params, x)` and ciphertext `(c1, c2)`:
///
/// 1. Compute the shared secret `s = c1^x mod p`.
/// 2. Compute the modular inverse `s_inv = s^{-1} mod p`.
/// 3. Recover `m = c2 · s_inv mod p`.
/// 4. Decode `m` back to bytes.
///
/// Returns the original plaintext bytes.
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> Result<Vec<u8>> {
    let m = decrypt_to_element(sk, ct)?;
    decode_message(&m)
}

/// Decrypt a packet produced by [`super::encrypt::encrypt_padded_authenticated`].
pub fn decrypt_padded_authenticated(
    sk: &SecretKey,
    packet: &[u8],
    mac_key: &[u8],
) -> Result<Vec<u8>> {
    let body = verify_and_extract_packet_body(
        packet,
        mac_key,
        super::encrypt::SECURE_PACKET_DOMAIN_NORMAL,
    )?;
    let block_size = *body.get(1).ok_or_else(|| {
        AnamorphError::DecryptionFailed("secure packet missing block size".into())
    })? as usize;
    let ct = deserialize_ciphertext_for_modulus(&body[2..], &sk.params.p)?;
    let padded = decrypt(sk, &ct)?;
    unpad_pkcs7(&padded, block_size)
}

/// Decrypt to the raw group element (before byte-decoding).
///
/// Exposed for the anamorphic layer which needs the raw element for
/// covert-message extraction.
pub fn decrypt_to_element(sk: &SecretKey, ct: &Ciphertext) -> Result<BigUint> {
    let p = &sk.params.p;

    // s = c1^x mod p
    let s = ct_modpow_boxed(&ct.c1, &sk.x, p)?;

    // s_inv = s^{p-2} mod p  (by Fermat's little theorem, since p is prime)
    let p_minus_2 = p - BigUint::from(2u32);
    let s_inv = s.modpow(&p_minus_2, p);

    // m = c2 * s_inv mod p
    let m = (&ct.c2 * &s_inv) % p;

    if m.is_zero() || m == BigUint::one() {
        // Sanity check — valid encoded messages have the 0x01 prefix,
        // so the decoded element is always > 1.
        // m=0 would indicate an invalid ciphertext.
    }

    Ok(m)
}

pub(crate) fn deserialize_ciphertext_for_modulus(
    bytes: &[u8],
    p: &BigUint,
) -> Result<Ciphertext> {
    let width = ((p.bits() + 7) / 8) as usize;
    if bytes.len() != width * 2 {
        return Err(AnamorphError::DecryptionFailed(
            "ciphertext payload length mismatch".into(),
        ));
    }

    let c1 = BigUint::from_bytes_be(&bytes[..width]);
    let c2 = BigUint::from_bytes_be(&bytes[width..]);
    let one = BigUint::one();

    if c1 <= one || c1 >= *p || c2 <= one || c2 >= *p {
        return Err(AnamorphError::DecryptionFailed(
            "ciphertext component out of range".into(),
        ));
    }

    Ok(Ciphertext { c1, c2 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normal::encrypt::encrypt;
    use crate::normal::encrypt::encrypt_padded_authenticated;
    use crate::normal::keygen::keygen;

    #[test]
    fn test_decrypt_roundtrip() {
        let (pk, sk) = keygen(64).expect("keygen");
        let msg = b"Hi!";
        let ct = encrypt(&pk, msg).expect("encrypt");
        let decrypted = decrypt(&sk, &ct).expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_decrypt_empty_message() {
        let (pk, sk) = keygen(64).expect("keygen");
        let msg = b"";
        let ct = encrypt(&pk, msg).expect("encrypt");
        let decrypted = decrypt(&sk, &ct).expect("decrypt");
        assert_eq!(decrypted, msg.to_vec());
    }

    #[test]
    fn test_decrypt_binary_data() {
        let (pk, sk) = keygen(64).expect("keygen");
        let msg: Vec<u8> = (0u8..5).collect();
        let ct = encrypt(&pk, &msg).expect("encrypt");
        let decrypted = decrypt(&sk, &ct).expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (pk, _sk) = keygen(64).expect("keygen");
        let (_, wrong_sk) = keygen(64).expect("keygen2");
        let msg = b"secret";
        let ct = encrypt(&pk, msg).expect("encrypt");
        // Decrypting with the wrong key should produce garbage, not the original message
        // (it might not error, but the decoded message will differ)
        let result = decrypt(&wrong_sk, &ct);
        match result {
            Ok(decrypted) => assert_ne!(decrypted, msg.to_vec()),
            Err(_) => {} // Also acceptable — decoding may fail
        }
    }

    #[test]
    fn test_secure_packet_rejects_tampered_tag() {
        let (pk, sk) = keygen(128).expect("keygen");
        let mac_key = b"0123456789abcdef";
        let mut packet = encrypt_padded_authenticated(&pk, b"ok", mac_key, 8)
            .expect("secure encrypt");

        let last = packet.len() - 1;
        packet[last] ^= 0x01;

        let result = decrypt_padded_authenticated(&sk, &packet, mac_key);
        assert!(matches!(result, Err(AnamorphError::IntegrityError)));
    }
}
