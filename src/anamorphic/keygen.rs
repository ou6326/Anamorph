//! Anamorphic key generation — `aGen(λ)`.
//!
//! Produces normal ElGamal keys **plus** a double key `dk` that is shared
//! between sender and receiver out-of-band.
//!
//! In the EC22 base scheme the double key is established once at key-generation
//! time.  The EC24 extension (implemented separately in `src/ec24/`) lifts this
//! restriction to allow multi-use double keys.

use crypto_bigint::{BoxedUint, NonZero, RandomMod};
use num_bigint::BigUint;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ct::ct_modpow_boxed;
use crate::errors::Result;
use crate::normal::keygen::{keygen_from_params, PublicKey, SecretKey};
use crate::params::{generate_group_params, GroupParams, InfallibleSysRng};

/// The anamorphic double key.
///
/// Shared secretly between sender and receiver.  Knowledge of `dk`
/// is required to:
/// - **Sender:** embed a covert message during encryption.
/// - **Receiver:** extract the covert message during decryption.
///
/// An adversary who extracts only the normal secret key `x` cannot
/// derive or detect the existence of `dk`.
///
/// ## Construction
///
/// The double key contains:
/// - `dk` — a random exponent in `[1, q-1]`
/// - `dk_pub` — the Diffie-Hellman public value `g^dk mod p`
///
/// Both sender and receiver can compute the shared secret for any
/// ciphertext `(c1, ...)` as:
/// - Sender:   `shared = dk_pub^r = g^(dk·r) mod p`
/// - Receiver: `shared = c1^dk = g^(r·dk) mod p`
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DoubleKey {
    /// The double-key secret exponent in `[1, q-1]`.
    pub dk: BoxedUint,
    /// The DH public value `g^dk mod p`.
    ///
    /// The sender uses this to compute the shared secret `dk_pub^r`
    /// for covert-message encryption.
    #[zeroize(skip)]
    pub dk_pub: BigUint,
}

impl DoubleKey {
    /// Compute the DH shared secret given the other party's ephemeral
    /// public value.
    ///
    /// - Sender calls with `ephemeral = g^dk` and their `r`:
    ///   `shared = dk_pub^r mod p`.
    /// - Receiver calls with `c1 = g^r`:
    ///   `shared = c1^dk mod p`.
    ///
    /// Both arrive at `g^(dk·r) mod p`.
    pub fn shared_secret(&self, ephemeral: &BigUint, p: &BigUint) -> BigUint {
        ct_modpow_boxed(ephemeral, &self.dk, p).expect("valid DH parameters")
    }
}

/// Anamorphic key generation — produces `(PublicKey, SecretKey, DoubleKey)`.
///
/// 1. Generate group parameters `(p, q, g)`.
/// 2. Run standard `keygen` to produce `(pk, sk)`.
/// 3. Choose `dk ← [1, q-1]` uniformly at random.
/// 4. Compute `dk_pub = g^dk mod p`.
///
/// The double key `dk` must be transmitted to the sender via a secure
/// out-of-band channel (including `dk_pub` or the full `DoubleKey`).
pub fn akeygen(bit_size: usize) -> Result<(PublicKey, SecretKey, DoubleKey)> {
    let params = generate_group_params(bit_size)?;
    akeygen_from_params(&params)
}

/// Anamorphic key generation from pre-existing group parameters.
pub fn akeygen_from_params(
    params: &GroupParams,
) -> Result<(PublicKey, SecretKey, DoubleKey)> {
    let (pk, sk) = keygen_from_params(params)?;

    let mut rng = InfallibleSysRng::new();
    let q_boxed = BoxedUint::from_be_slice_vartime(&params.q.to_bytes_be());
    let q_nonzero = NonZero::new(q_boxed).expect("q must be non-zero");

    let dk = loop {
        let candidate = BoxedUint::try_random_mod_vartime(&mut rng, &q_nonzero)
            .expect("system RNG failure");
        if candidate.is_zero().into() {
            continue;
        }
        break candidate;
    };

    let dk_pub = ct_modpow_boxed(&params.g, &dk, &params.p)?;

    let dk = DoubleKey {
        dk,
        dk_pub,
    };

    Ok((pk, sk, dk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigUint, RandBigInt};
    use crate::params::validate_group_membership;
    use num_traits::One;

    #[test]
    fn test_akeygen_produces_valid_keys() {
        let (pk, sk, dk) = akeygen(64).expect("akeygen");

        // Public key in group
        validate_group_membership(&pk.h, &pk.params.p, &pk.params.q)
            .expect("h in group");

        // Secret key in range
        let x = BigUint::from_bytes_be(&sk.x.to_be_bytes());
        assert!(x >= BigUint::one());
        assert!(x < sk.params.q);

        // Double key exponent in range
        let dk_value = BigUint::from_bytes_be(&dk.dk.to_be_bytes());
        assert!(dk_value >= BigUint::one());
        assert!(dk_value < pk.params.q);

        // dk_pub = g^dk mod p must be in the group
        validate_group_membership(&dk.dk_pub, &pk.params.p, &pk.params.q)
            .expect("dk_pub in group");

        // Verify dk_pub = g^dk mod p
        let expected_dk_pub = ct_modpow_boxed(&pk.params.g, &dk.dk, &pk.params.p).expect("dk_pub");
        assert_eq!(dk.dk_pub, expected_dk_pub);
    }

    #[test]
    fn test_akeygen_from_params() {
        let params = generate_group_params(64).expect("params");
        let (pk, _, dk) = akeygen_from_params(&params).expect("akeygen");

        assert_eq!(pk.params, params);
        let dk_value = BigUint::from_bytes_be(&dk.dk.to_be_bytes());
        assert!(dk_value >= BigUint::one());
        assert!(dk_value < params.q);

        // Verify dk_pub
        let expected = ct_modpow_boxed(&params.g, &dk.dk, &params.p).expect("dk_pub");
        assert_eq!(dk.dk_pub, expected);
    }

    #[test]
    fn test_shared_secret_consistency() {
        let (pk, _, dk) = akeygen(64).expect("akeygen");
        let p = &pk.params.p;
        let g = &pk.params.g;

        // Simulate sender with random r
        let mut rng = rand::thread_rng();
        let r = rng.gen_biguint_range(&BigUint::one(), &pk.params.q);

        // Sender computes shared = dk_pub^r mod p
        let sender_shared = dk.dk_pub.modpow(&r, p);

        // Receiver sees c1 = g^r and computes shared = c1^dk mod p
        let c1 = g.modpow(&r, p);
        let receiver_shared = dk.shared_secret(&c1, p);

        assert_eq!(sender_shared, receiver_shared);
    }
}
