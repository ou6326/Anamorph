//! ElGamal encryption — `Enc(pk, m)`.
//!
//! Encrypts a byte-string message under a public key using standard
//! ElGamal.  The message is encoded as a `BigUint` and must satisfy
//! `1 ≤ m < p`.

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::thread_rng;

use crate::errors::{AnamorphError, Result};
use super::keygen::PublicKey;

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
    // Prepend 0x01 to ensure the encoding is always > 0
    let mut padded = vec![0x01];
    padded.extend_from_slice(msg);
    let m = BigUint::from_bytes_be(&padded);

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

/// Standard ElGamal encryption.
///
/// Given public key `pk = (params, h)` and plaintext bytes `msg`:
///
/// 1. Encode `msg` as group element `m`.
/// 2. Pick `r ← [1, q-1]` uniformly at random.
/// 3. Compute `c1 = g^r mod p`, `c2 = m · h^r mod p`.
///
/// Returns `Ciphertext { c1, c2 }`.
pub fn encrypt(pk: &PublicKey, msg: &[u8]) -> Result<Ciphertext> {
    let m = encode_message(msg, &pk.params.p)?;
    let mut rng = thread_rng();
    let r = rng.gen_biguint_range(&BigUint::one(), &pk.params.q);
    encrypt_with_randomness(pk, &m, &r)
}

/// ElGamal encryption with explicit randomness.
///
/// This is the internal workhorse used by both `encrypt` (which generates
/// fresh randomness) and `aencrypt` (which derives randomness from the
/// double key + covert message).
///
/// `m` must already be a valid encoded group element (see [`encode_message`]).
pub fn encrypt_with_randomness(
    pk: &PublicKey,
    m: &BigUint,
    r: &BigUint,
) -> Result<Ciphertext> {
    let p = &pk.params.p;
    let g = &pk.params.g;
    let h = &pk.h;

    // c1 = g^r mod p
    let c1 = g.modpow(r, p);

    // c2 = m * h^r mod p
    let hr = h.modpow(r, p);
    let c2 = (m * &hr) % p;

    Ok(Ciphertext { c1, c2 })
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let ct = encrypt(&pk, b"test").expect("encrypt");
        // c1 and c2 should be non-zero
        assert!(!ct.c1.is_zero());
        assert!(!ct.c2.is_zero());
    }

    #[test]
    fn test_different_encryptions_differ() {
        let (pk, _) = keygen(64).expect("keygen");
        let ct1 = encrypt(&pk, b"test").expect("encrypt1");
        let ct2 = encrypt(&pk, b"test").expect("encrypt2");
        // Different random r means different ciphertexts (with overwhelming probability)
        assert_ne!(ct1, ct2);
    }
}
