//! ElGamal encryption — `Enc(pk, m)`.
//!
//! Encrypts a byte-string message under a public key using standard
//! ElGamal.  The message is encoded as a `BigUint` and must satisfy
//! `1 ≤ m < p`.

use crypto_bigint::BoxedUint;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use zeroize::Zeroize;

use super::keygen::PublicKey;
use crate::errors::{AnamorphError, Result};
use crate::hardening::{generate_mac, MAC_SIZE};
use crate::padding::pad_pkcs7;

pub(crate) const SECURE_PACKET_VERSION: u8 = 1;
pub(crate) const SECURE_PACKET_DOMAIN_NORMAL: u8 = 1;
pub(crate) const SECURE_PACKET_DOMAIN_ANAMORPHIC_PRF: u8 = 2;
pub(crate) const SECURE_PACKET_DOMAIN_ANAMORPHIC_STREAM: u8 = 3;
pub(crate) const SECURE_PACKET_DOMAIN_ANAMORPHIC_XOR: u8 = 4;

/// ElGamal ciphertext `(c1, c2)`.
///
/// - `c1 = g^r mod p`
/// - `c2 = m · h^r mod p`
///
/// where `r` is a fresh random exponent in `[1, q-1]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    /// First component: `g^r mod p`.
    pub c1: BigUint,
    /// Second component: `m · h^r mod p`.
    pub c2: BigUint,
}

/// Encode a byte slice as a group element.
///
/// Prepends a 0x01 byte to guarantee the value is positive and non-zero,
/// then checks that the result is less than `p`.
pub fn encode_message(msg: &[u8], p: &BigUint) -> Result<BigUint> {
    // Bound check first to avoid constructing oversized intermediates.
    let p_width = ((p.bits() + 7) / 8) as usize;
    if msg.len() + 1 > p_width {
        return Err(AnamorphError::MessageTooLarge);
    }

    // Prepend 0x01 to ensure the encoding is always > 0.
    let mut encoded = Vec::with_capacity(msg.len() + 1);
    encoded.push(0x01);
    encoded.extend_from_slice(msg);
    let m = BigUint::from_bytes_be(&encoded);

    if &m >= p {
        return Err(AnamorphError::MessageTooLarge);
    }

    Ok(m)
}

/// Decode a group element back to the original message bytes.
///
/// Strips the leading 0x01 byte that was prepended during encoding.
pub fn decode_message(m: &BigUint) -> Result<Vec<u8>> {
    let bytes = m.to_bytes_be();
    if bytes.is_empty() || bytes[0] != 0x01 {
        return Err(AnamorphError::DecryptionFailed(
            "invalid message encoding: missing 0x01 prefix".into(),
        ));
    }
    Ok(bytes[1..].to_vec())
}

/// Decode a fixed-width boxed group element back to the original message bytes.
pub(crate) fn decode_message_boxed(m: &BoxedUint) -> Result<Vec<u8>> {
    let mut bytes = m.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let decoded = if first_nonzero >= bytes.len() || bytes[first_nonzero] != 0x01 {
        Err(AnamorphError::DecryptionFailed(
            "invalid message encoding: missing 0x01 prefix".into(),
        ))
    } else {
        Ok(bytes[first_nonzero + 1..].to_vec())
    };
    bytes.zeroize();
    decoded
}

/// Standard ElGamal encryption.
///
/// Given public key `pk = (params, h)` and plaintext bytes `msg`:
///
/// 1. Encode `msg` as group element `m`.
/// 2. Pick `r ← [1, q-1]` uniformly at random.
/// 3. Compute `c1 = g^r mod p`, `c2 = m · h^r mod p`.
///
/// Returns `Ciphertext { c1, c2 }`.
pub fn encrypt_legacy(pk: &PublicKey, msg: &[u8]) -> Result<Ciphertext> {
    let m = encode_message(msg, &pk.params.p)?;
    let mut rng = rand::thread_rng();
    let r = rng.gen_biguint_range(&BigUint::one(), &pk.params.q);
    encrypt_with_randomness(pk, &m, &r)
}

/// Encrypt with PKCS#7 padding and HMAC authentication.
///
/// Output packet format:
/// `version || domain || block_size || c1_fixed || c2_fixed || tag`.
pub fn encrypt(
    pk: &PublicKey,
    msg: &[u8],
    mac_key: &[u8],
    block_size: usize,
) -> Result<Vec<u8>> {
    let padded = pad_pkcs7(msg, block_size)?;
    let ct = encrypt_legacy(pk, &padded)?;
    let ct_bytes = serialize_ciphertext_for_modulus(&ct, &pk.params.p)?;

    let block_size_u8 = u8::try_from(block_size).map_err(|_| {
        AnamorphError::InvalidParameter("block size must fit in one byte".into())
    })?;

    // Include Version in the authenticated envelope
    let mut packet = Vec::with_capacity(1 + 2 + ct_bytes.len() + MAC_SIZE);
    packet.push(SECURE_PACKET_VERSION);
    packet.push(SECURE_PACKET_DOMAIN_NORMAL);
    packet.push(block_size_u8);
    packet.extend_from_slice(&ct_bytes);

    let tag = generate_mac(mac_key, &packet)?;
    packet.extend_from_slice(&tag);
    Ok(packet)
}

/// ElGamal encryption with explicit randomness.
///
/// This is the internal workhorse used by both `encrypt` (which generates
/// fresh randomness) and `aencrypt` (which derives randomness from the
/// double key + covert message).
///
/// `m` must already be a valid encoded group element (see [`encode_message`]).
pub fn encrypt_with_randomness(pk: &PublicKey, m: &BigUint, r: &BigUint) -> Result<Ciphertext> {
    let p = &pk.params.p;
    let g = &pk.params.g;
    let h = &pk.h;

    // Use constant-time modular exponentiation to protect the secret randomness `r`
    let c1 = crate::ct::ct_modpow_biguint(g, r, p)?;

    let hr = crate::ct::ct_modpow_biguint(h, r, p)?;
    // Use constant-time modular multiplication to protect the shared secret `hr`
    let c2 = crate::ct::ct_mul_mod_biguint(m, &hr, p)?;

    Ok(Ciphertext { c1, c2 })
}

pub(crate) fn serialize_ciphertext_for_modulus(ct: &Ciphertext, p: &BigUint) -> Result<Vec<u8>> {
    let width = ((p.bits() + 7) / 8) as usize;
    let c1_bytes = ct.c1.to_bytes_be();
    let c2_bytes = ct.c2.to_bytes_be();

    if c1_bytes.len() > width || c2_bytes.len() > width {
        return Err(AnamorphError::DecryptionFailed(
            "ciphertext component does not fit modulus width".into(),
        ));
    }

    let mut out = vec![0u8; width * 2];
    out[width - c1_bytes.len()..width].copy_from_slice(&c1_bytes);
    out[2 * width - c2_bytes.len()..2 * width].copy_from_slice(&c2_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normal::decrypt::decrypt;
    use crate::normal::keygen::keygen;
    use num_traits::Zero;

    #[test]
    fn test_encode_decode_roundtrip() {
        let (pk, _) = keygen(64).expect("keygen");
        let msg = b"hello";
        let encoded = encode_message(msg, &pk.params.p).expect("encode");
        let decoded = decode_message(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_encode_empty_message() {
        let (pk, _) = keygen(64).expect("keygen");
        let msg = b"";
        let encoded = encode_message(msg, &pk.params.p).expect("encode");
        let decoded = decode_message(&encoded).expect("decode");
        assert_eq!(decoded, msg.to_vec());
    }

    #[test]
    fn test_encrypt_produces_ciphertext() {
        let (pk, _) = keygen(64).expect("keygen");
        let ct = encrypt_legacy(&pk, b"test").expect("encrypt");
        // c1 and c2 should be non-zero
        assert!(!ct.c1.is_zero());
        assert!(!ct.c2.is_zero());
    }

    #[test]
    fn test_different_encryptions_differ() {
        let (pk, _) = keygen(64).expect("keygen");
        let ct1 = encrypt_legacy(&pk, b"test").expect("encrypt1");
        let ct2 = encrypt_legacy(&pk, b"test").expect("encrypt2");
        // Different random r means different ciphertexts (with overwhelming probability)
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_secure_packet_roundtrip() {
        let (pk, sk) = keygen(128).expect("keygen");
        let mac_key = b"0123456789abcdef";

        let packet = encrypt(&pk, b"ok", mac_key, 8)
            .expect("secure encrypt");
        let plain = decrypt(&sk, &packet, mac_key)
            .expect("secure decrypt");

        assert_eq!(plain, b"ok");
    }
}
