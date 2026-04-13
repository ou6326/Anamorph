//! Anamorphic encryption — `aEnc(pk, dk, m_normal, m_covert)`.
//!
//! Provides two complementary covert-channel constructions:
//!
//! ## 1. PRF-Based (single ciphertext, known message space)
//!
//! Derives `r = HMAC(dk, m_covert) mod q` and encrypts with that randomness.
//! The ciphertext is syntactically identical to normal ElGamal.  The receiver
//! verifies candidates by checking `g^{H(dk, m')} ≡ c1`.
//!
//! Best for: small, pre-agreed message spaces (codes, flags, single bits).
//!
//! ## 2. DH-Based with rejection sampling (multi-ciphertext, arbitrary messages)
//!
//! Each covert byte is encoded in a separate ciphertext.  For each byte:
//! 1. Pick random `r`, compute `c1 = g^r mod p`.
//! 2. Compute `shared = dk_pub^r mod p` (sender side) = `c1^dk mod p` (receiver side).
//! 3. Compute `mask = SHA-256(shared)[0]` — one byte of keystream.
//! 4. If `mask == covert_byte`, accept `r`; otherwise retry.
//! 5. Expected 256 tries per byte.
//!
//! The receiver extracts: `covert_byte = SHA-256(c1^dk mod p)[0]`.
//!
//! Best for: arbitrary-length covert messages transmitted across a stream of ciphertexts.

use crypto_bigint::{BoxedUint, NonZero};
use hmac::{Hmac, KeyInit, Mac};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::keygen::DoubleKey;
use crate::ct::ct_modpow_boxed;
use crate::errors::{AnamorphError, Result};
use crate::hardening::{generate_mac, MAC_SIZE};
use crate::normal::encrypt::{
    encode_message,
    encrypt_with_randomness,
    serialize_ciphertext_for_modulus,
    Ciphertext,
    SECURE_PACKET_DOMAIN_ANAMORPHIC_PRF,
    SECURE_PACKET_DOMAIN_ANAMORPHIC_STREAM,
    SECURE_PACKET_DOMAIN_ANAMORPHIC_XOR,
    SECURE_PACKET_VERSION,
};
use crate::normal::keygen::PublicKey;
use crate::padding::pad_pkcs7;

type HmacSha256 = Hmac<Sha256>;

// =========================================================================
// 1. PRF-Based anamorphic encryption (single ciphertext)
// =========================================================================

/// Anamorphic encryption using PRF-derived randomness (EC22 base scheme).
///
/// Encrypts `normal_msg` under `pk` while embedding `covert_msg` in the
/// ciphertext's randomness via the double key `dk`.
///
/// The resulting ciphertext is indistinguishable from a normal ElGamal
/// ciphertext to any party without `dk`.
///
/// # Limitations
///
/// The receiver must know the covert message space to recover
/// `covert_msg` (via candidate verification or brute-force search).
/// For arbitrary-length extraction, use [`aencrypt_stream`] instead.
pub fn aencrypt(
    pk: &PublicKey,
    dk: &DoubleKey,
    normal_msg: &[u8],
    covert_msg: &[u8],
) -> Result<Ciphertext> {
    let m_normal = encode_message(normal_msg, &pk.params.p)?;
    let r = derive_randomness(dk, covert_msg, &pk.params.q);
    encrypt_with_boxed_randomness(pk, &m_normal, &r)
}

/// PRF-mode anamorphic encryption with PKCS#7 padding and HMAC authentication.
pub fn aencrypt_padded_authenticated(
    pk: &PublicKey,
    dk: &DoubleKey,
    normal_msg: &[u8],
    covert_msg: &[u8],
    mac_key: &[u8],
    block_size: usize,
) -> Result<Vec<u8>> {
    let padded = pad_pkcs7(normal_msg, block_size)?;
    let ct = aencrypt(pk, dk, &padded, covert_msg)?;
    let ct_body = serialize_ciphertext_for_modulus(&ct, &pk.params.p)?;
    let block_size_u8 = u8::try_from(block_size).map_err(|_| {
        AnamorphError::InvalidParameter("block size must fit in one byte".into())
    })?;

    let mut body = Vec::with_capacity(2 + ct_body.len());
    body.push(SECURE_PACKET_DOMAIN_ANAMORPHIC_PRF);
    body.push(block_size_u8);
    body.extend_from_slice(&ct_body);

    let tag = generate_mac(mac_key, &body)?;
    let mut packet = Vec::with_capacity(1 + body.len() + MAC_SIZE);
    packet.push(SECURE_PACKET_VERSION);
    packet.extend_from_slice(&body);
    packet.extend_from_slice(&tag);
    Ok(packet)
}

/// Derive encryption randomness `r` from the double key and covert message.
///
/// Uses HMAC-SHA256 as a PRF:
///   `r = HMAC-SHA256(dk, covert_msg) mod q`
///
/// The output is reduced modulo `q` and clamped to `[1, q-1]`.
pub(crate) fn derive_randomness(dk: &DoubleKey, covert_msg: &[u8], q: &BigUint) -> BoxedUint {
    let mut dk_bytes = dk.dk.to_be_bytes().to_vec();

    let mut mac = HmacSha256::new_from_slice(&dk_bytes).expect("HMAC accepts any key length");
    mac.update(covert_msg);
    let mut result = mac.finalize().into_bytes();

    let q_byte_len = (q.bits() as usize + 7) / 8;
    let mut hash_bytes = result.to_vec();
    result.zeroize();

    // Chain HMAC invocations in counter mode for large q.
    let mut counter = 1u32;
    while hash_bytes.len() < q_byte_len + 16 {
        let mut mac = HmacSha256::new_from_slice(&dk_bytes).expect("HMAC accepts any key length");
        mac.update(covert_msg);
        mac.update(&counter.to_be_bytes());
        let mut extra = mac.finalize().into_bytes();
        hash_bytes.extend_from_slice(&extra);
        extra.zeroize();
        counter += 1;
    }

    dk_bytes.zeroize();

    let q_bytes = q.to_bytes_be();
    let q_boxed = BoxedUint::from_be_slice_vartime(&q_bytes);
    let q_nz = NonZero::new(q_boxed).expect("q must be non-zero");

    let mut hash_boxed = BoxedUint::from_be_slice_vartime(&hash_bytes);
    let mut r = hash_boxed.rem_vartime(&q_nz);
    hash_boxed.zeroize();
    hash_bytes.zeroize();

    if r.is_zero().into() {
        // Keep PRF mapping deterministic while preserving ElGamal invariant r in [1, q-1].
        r = BoxedUint::one_with_precision(r.bits_precision());
    }

    r
}

fn encrypt_with_boxed_randomness(pk: &PublicKey, m: &BigUint, r: &BoxedUint) -> Result<Ciphertext> {
    let p = &pk.params.p;
    let g = &pk.params.g;
    let h = &pk.h;

    let c1 = ct_modpow_boxed(g, r, p)?;
    let hr = ct_modpow_boxed(h, r, p)?;
    let c2 = (m * &hr) % p;

    Ok(Ciphertext { c1, c2 })
}

// =========================================================================
// 2. DH-Based anamorphic encryption (multi-ciphertext, direct extraction)
// =========================================================================

/// Anamorphic encryption with direct extraction for arbitrary-length covert messages.
///
/// Produces **one ciphertext per covert byte**.  Each ciphertext carries
/// one byte of `covert_msg` embedded via rejection sampling on the DH
/// shared secret.  All ciphertexts encrypt `normal_msg` normally.
///
/// The receiver extracts covert bytes by computing `SHA-256(c1^dk mod p)[0]`
/// for each ciphertext — no brute-force or candidate knowledge required.
///
/// # Arguments
///
/// - `pk` — receiver's public key
/// - `dk` — shared double key (must include `dk_pub`)
/// - `normal_msg` — plaintext visible to anyone with `sk`
/// - `covert_msg` — arbitrary-length hidden payload
/// - `max_tries_per_byte` — rejection sampling budget per byte (default: 65536)
///
/// # Returns
///
/// A vector of ciphertexts, each encrypting `normal_msg` and carrying one
/// covert byte.  The vector length equals `covert_msg.len()`.
pub fn aencrypt_stream(
    pk: &PublicKey,
    dk: &DoubleKey,
    normal_msg: &[u8],
    covert_msg: &[u8],
    max_tries_per_byte: Option<u32>,
) -> Result<Vec<Ciphertext>> {
    let max_tries = max_tries_per_byte.unwrap_or(65536);
    let m_normal = encode_message(normal_msg, &pk.params.p)?;
    let mut rng = rand::thread_rng();
    let one = BigUint::one();

    let mut ciphertexts = Vec::with_capacity(covert_msg.len());

    for &covert_byte in covert_msg {
        let mut found = false;

        for _ in 0..max_tries {
            // Pick random r
            let r = rng.gen_biguint_range(&one, &pk.params.q);

            // Compute c1 = g^r mod p
            let c1 = pk.params.g.modpow(&r, &pk.params.p);

            // Compute shared secret = dk_pub^r mod p
            let shared = dk.dk_pub.modpow(&r, &pk.params.p);

            // Derive mask byte from the shared secret
            let mask = shared_to_byte(&shared);

            if mask == covert_byte {
                // This r encodes our covert byte — encrypt with it
                let ct = encrypt_with_randomness(pk, &m_normal, &r)?;
                debug_assert_eq!(ct.c1, c1);
                ciphertexts.push(ct);
                found = true;
                break;
            }
        }

        if !found {
            return Err(AnamorphError::DecryptionFailed(format!(
                "rejection sampling exhausted for covert byte 0x{:02x} \
                 after {max_tries} tries",
                covert_byte
            )));
        }
    }

    Ok(ciphertexts)
}

/// DH stream-mode encryption with per-ciphertext authenticated packets.
pub fn aencrypt_stream_padded_authenticated(
    pk: &PublicKey,
    dk: &DoubleKey,
    normal_msg: &[u8],
    covert_msg: &[u8],
    mac_key: &[u8],
    block_size: usize,
    max_tries_per_byte: Option<u32>,
) -> Result<Vec<Vec<u8>>> {
    let padded = pad_pkcs7(normal_msg, block_size)?;
    let cts = aencrypt_stream(pk, dk, &padded, covert_msg, max_tries_per_byte)?;
    let block_size_u8 = u8::try_from(block_size).map_err(|_| {
        AnamorphError::InvalidParameter("block size must fit in one byte".into())
    })?;

    let mut packets = Vec::with_capacity(cts.len());
    for ct in cts {
        let ct_body = serialize_ciphertext_for_modulus(&ct, &pk.params.p)?;
        let mut body = Vec::with_capacity(2 + ct_body.len());
        body.push(SECURE_PACKET_DOMAIN_ANAMORPHIC_STREAM);
        body.push(block_size_u8);
        body.extend_from_slice(&ct_body);

        let tag = generate_mac(mac_key, &body)?;
        let mut packet = Vec::with_capacity(1 + body.len() + MAC_SIZE);
        packet.push(SECURE_PACKET_VERSION);
        packet.extend_from_slice(&body);
        packet.extend_from_slice(&tag);
        packets.push(packet);
    }

    Ok(packets)
}

/// Anamorphic encryption using DH-XOR method (single ciphertext, fast).
///
/// Instead of rejection sampling, this method embeds the covert message
/// using XOR with a keystream derived from the DH shared secret.
///
/// **Trade-off:** The covert message is encoded in metadata alongside
/// the ciphertext rather than being steganographically hidden in `r`.
/// Use this when the ciphertext-count channel is not an issue (e.g.,
/// the normal-mode stream also sends multiple messages).
///
/// Returns `(ciphertext, covert_encrypted_bytes)` where the encrypted
/// bytes must be transmitted alongside the ciphertext.
///
/// The receiver decrypts with [`super::decrypt::adecrypt_xor`].
pub fn aencrypt_xor(
    pk: &PublicKey,
    dk: &DoubleKey,
    normal_msg: &[u8],
    covert_msg: &[u8],
) -> Result<(Ciphertext, Vec<u8>)> {
    let m_normal = encode_message(normal_msg, &pk.params.p)?;
    let mut rng = rand::thread_rng();
    let r = rng.gen_biguint_range(&BigUint::one(), &pk.params.q);

    // Encrypt normal message
    let ct = encrypt_with_randomness(pk, &m_normal, &r)?;

    // Compute shared secret: dk_pub^r = g^(dk·r) mod p
    let shared = dk.dk_pub.modpow(&r, &pk.params.p);

    // Derive keystream from the shared secret
    let keystream = derive_keystream(&shared, covert_msg.len());

    // XOR covert message with keystream
    let covert_encrypted: Vec<u8> = covert_msg
        .iter()
        .zip(keystream.iter())
        .map(|(m, k)| m ^ k)
        .collect();

    Ok((ct, covert_encrypted))
}

/// DH XOR-mode encryption with authenticated packet wrapping.
pub fn aencrypt_xor_padded_authenticated(
    pk: &PublicKey,
    dk: &DoubleKey,
    normal_msg: &[u8],
    covert_msg: &[u8],
    mac_key: &[u8],
    block_size: usize,
) -> Result<Vec<u8>> {
    let padded = pad_pkcs7(normal_msg, block_size)?;
    let (ct, covert_encrypted) = aencrypt_xor(pk, dk, &padded, covert_msg)?;
    let ct_body = serialize_ciphertext_for_modulus(&ct, &pk.params.p)?;
    let block_size_u8 = u8::try_from(block_size).map_err(|_| {
        AnamorphError::InvalidParameter("block size must fit in one byte".into())
    })?;
    let covert_len = u32::try_from(covert_encrypted.len()).map_err(|_| {
        AnamorphError::InvalidParameter("covert payload too large".into())
    })?;

    let mut body = Vec::with_capacity(2 + ct_body.len() + 4 + covert_encrypted.len());
    body.push(SECURE_PACKET_DOMAIN_ANAMORPHIC_XOR);
    body.push(block_size_u8);
    body.extend_from_slice(&ct_body);
    body.extend_from_slice(&covert_len.to_be_bytes());
    body.extend_from_slice(&covert_encrypted);

    let tag = generate_mac(mac_key, &body)?;
    let mut packet = Vec::with_capacity(1 + body.len() + MAC_SIZE);
    packet.push(SECURE_PACKET_VERSION);
    packet.extend_from_slice(&body);
    packet.extend_from_slice(&tag);
    Ok(packet)
}

// =========================================================================
// Helpers
// =========================================================================

/// Extract one byte from a DH shared secret.
///
/// Uses SHA-256 to hash the shared point and returns the first byte.
/// This is the extraction function used by both sender (rejection sampling)
/// and receiver (direct extraction).
pub(crate) fn shared_to_byte(shared: &BigUint) -> u8 {
    let mut shared_bytes = shared.to_bytes_be();
    let hash = Sha256::digest(&shared_bytes);
    shared_bytes.zeroize();
    hash[0]
}

/// Derive a keystream of `length` bytes from a DH shared secret.
///
/// Uses SHA-256 in counter mode: `keystream[i..i+32] = SHA-256(shared || counter)`.
pub(crate) fn derive_keystream(shared: &BigUint, length: usize) -> Vec<u8> {
    let mut shared_bytes = shared.to_bytes_be();
    let mut keystream = Vec::with_capacity(length);
    let mut counter = 0u32;

    while keystream.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(&shared_bytes);
        hasher.update(&counter.to_be_bytes());
        let block = hasher.finalize();
        keystream.extend_from_slice(&block);
        counter += 1;
    }

    keystream.truncate(length);
    shared_bytes.zeroize();
    keystream
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anamorphic::keygen::akeygen;
    use crate::normal::decrypt::decrypt;
    use num_traits::{One, Zero};

    fn derive_randomness_raw_mod_q(dk: &DoubleKey, covert_msg: &[u8], q: &BigUint) -> BigUint {
        let dk_bytes = dk.dk.to_be_bytes().to_vec();

        let mut mac = HmacSha256::new_from_slice(&dk_bytes).expect("HMAC accepts any key length");
        mac.update(covert_msg);
        let result = mac.finalize().into_bytes();

        let q_byte_len = (q.bits() as usize + 7) / 8;
        let mut hash_bytes = result.to_vec();

        let mut counter = 1u32;
        while hash_bytes.len() < q_byte_len + 16 {
            let mut mac =
                HmacSha256::new_from_slice(&dk_bytes).expect("HMAC accepts any key length");
            mac.update(covert_msg);
            mac.update(&counter.to_be_bytes());
            let extra = mac.finalize().into_bytes();
            hash_bytes.extend_from_slice(&extra);
            counter += 1;
        }

        BigUint::from_bytes_be(&hash_bytes) % q
    }

    // ----- PRF-based tests -----

    #[test]
    fn test_aencrypt_normal_decrypt_recovers_normal_msg() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        let normal_msg = b"hi";
        let covert_msg = b"sec";

        let ct = aencrypt(&pk, &dk, normal_msg, covert_msg).expect("aencrypt");
        let decrypted = decrypt(&sk, &ct).expect("decrypt");
        assert_eq!(decrypted, normal_msg.to_vec());
    }

    #[test]
    fn test_aencrypt_deterministic_with_same_inputs() {
        let (pk, _, dk) = akeygen(64).expect("akeygen");
        let ct1 = aencrypt(&pk, &dk, b"hello", b"secret").expect("aencrypt1");
        let ct2 = aencrypt(&pk, &dk, b"hello", b"secret").expect("aencrypt2");
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_aencrypt_different_covert_different_ciphertext() {
        let (pk, _, dk) = akeygen(64).expect("akeygen");
        let ct1 = aencrypt(&pk, &dk, b"hello", b"secret1").expect("aencrypt1");
        let ct2 = aencrypt(&pk, &dk, b"hello", b"secret2").expect("aencrypt2");
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_derive_randomness_in_range() {
        let (_, _, dk) = akeygen(64).expect("akeygen");
        let q = BigUint::from(1000003u64);
        let r = derive_randomness(&dk, b"test", &q);
        let r_big = BigUint::from_bytes_be(&r.to_be_bytes());
        assert!(r_big >= BigUint::one());
        assert!(r_big < q);
    }

    #[test]
    fn test_derive_randomness_zero_maps_to_one() {
        let (_, _, dk) = akeygen(64).expect("akeygen");
        let q = BigUint::from(257u32);

        let mut found_msg: Option<[u8; 4]> = None;
        for i in 0u32..200_000 {
            let msg = i.to_be_bytes();
            let raw = derive_randomness_raw_mod_q(&dk, &msg, &q);
            if raw.is_zero() {
                found_msg = Some(msg);
                break;
            }
        }

        let msg = found_msg.expect("must find an input that yields raw PRF mod q == 0");
        let mapped = derive_randomness(&dk, &msg, &q);
        let mapped_big = BigUint::from_bytes_be(&mapped.to_be_bytes());
        assert_eq!(mapped_big, BigUint::one());
    }

    // ----- XOR-based tests -----

    #[test]
    fn test_aencrypt_xor_normal_decrypt() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");
        let (ct, _covert_enc) =
            aencrypt_xor(&pk, &dk, b"hi", b"covert payload").expect("aencrypt_xor");

        // Normal decryption still works
        let decrypted = decrypt(&sk, &ct).expect("decrypt");
        assert_eq!(decrypted, b"hi".to_vec());
    }

    #[test]
    fn test_aencrypt_xor_covert_roundtrip() {
        let (pk, _, dk) = akeygen(64).expect("akeygen");
        let covert_msg = b"arbitrary length covert message!";

        let (ct, covert_encrypted) =
            aencrypt_xor(&pk, &dk, b"hi", covert_msg).expect("aencrypt_xor");

        // Receiver computes shared secret: c1^dk mod p
        let shared = dk.shared_secret(&ct.c1, &pk.params.p);
        let keystream = derive_keystream(&shared, covert_msg.len());
        let recovered: Vec<u8> = covert_encrypted
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        assert_eq!(recovered, covert_msg.to_vec());
    }

    // ----- Helper tests -----

    #[test]
    fn test_derive_keystream_length() {
        let shared = BigUint::from(12345u32);
        let ks = derive_keystream(&shared, 100);
        assert_eq!(ks.len(), 100);
    }

    #[test]
    fn test_derive_keystream_deterministic() {
        let shared = BigUint::from(12345u32);
        let ks1 = derive_keystream(&shared, 64);
        let ks2 = derive_keystream(&shared, 64);
        assert_eq!(ks1, ks2);
    }
}
