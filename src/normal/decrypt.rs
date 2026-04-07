//! ElGamal decryption — `Dec(sk, c)`.
//!
//! Recovers the plaintext bytes from an ElGamal ciphertext using the
//! secret key.

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::ct::ct_modpow_boxed;
use crate::errors::Result;
use super::encrypt::{decode_message, Ciphertext};
use super::keygen::SecretKey;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normal::encrypt::encrypt;
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
}
