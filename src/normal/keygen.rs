//! ElGamal key generation — `Gen(λ)`.
//!
//! Produces a public key `(params, h = g^x mod p)` and a secret key `x`,
//! where `x` is uniformly random in `[1, q-1]`.

use crypto_bigint::{BoxedUint, NonZero, RandomMod};
use core::fmt;
use num_bigint::BigUint;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ct::ct_modpow_boxed;
use crate::errors::Result;
use crate::params::{generate_group_params, GroupParams, InfallibleSysRng};

/// ElGamal public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Underlying group parameters (p, q, g).
    pub params: GroupParams,
    /// Public value `h = g^x mod p`.
    pub h: BigUint,
}

/// ElGamal secret key.
///
/// `x` is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Underlying group parameters (p, q, g).
    #[zeroize(skip)]
    pub params: GroupParams,
    /// Secret exponent in `[1, q-1]`.
    pub x: BoxedUint,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("params", &self.params)
            .field("x", &"<redacted>")
            .finish()
    }
}

/// Standard ElGamal key generation.
///
/// 1. Generate group parameters `(p, q, g)` with a safe prime of
///    `bit_size` bits.
/// 2. Choose `x ← [1, q-1]` uniformly at random.
/// 3. Compute `h = g^x mod p`.
///
/// Returns `(PublicKey, SecretKey)`.
pub fn keygen(bit_size: usize) -> Result<(PublicKey, SecretKey)> {
    let params = generate_group_params(bit_size)?;
    let (pk, sk) = keygen_from_params(&params)?;
    Ok((pk, sk))
}

/// Key generation from pre-existing group parameters.
///
/// Useful when multiple key pairs should share the same group, or for
/// testing with fixed parameters.
pub fn keygen_from_params(params: &GroupParams) -> Result<(PublicKey, SecretKey)> {
    let mut rng = InfallibleSysRng::new();
    let q_boxed = BoxedUint::from_be_slice_vartime(&params.q.to_bytes_be());
    let q_nonzero = NonZero::new(q_boxed).expect("q must be non-zero");

    // x ← [1, q-1]
    let x = loop {
        let candidate = BoxedUint::try_random_mod_vartime(&mut rng, &q_nonzero)
            .expect("system RNG failure");
        if candidate.is_zero().into() {
            continue;
        }
        break candidate;
    };

    // h = g^x mod p
    let h = ct_modpow_boxed(&params.g, &x, &params.p)?;

    let pk = PublicKey {
        params: params.clone(),
        h,
    };

    let sk = SecretKey {
        params: params.clone(),
        x,
    };

    Ok((pk, sk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::validate_group_membership;
    use num_traits::One;

    #[test]
    fn test_keygen_valid_public_key() {
        let (pk, _sk) = keygen(64).expect("keygen");
        // h must be in the order-q subgroup
        validate_group_membership(&pk.h, &pk.params.p, &pk.params.q)
            .expect("h should be in the group");
    }

    #[test]
    fn test_keygen_secret_key_in_range() {
        let (_pk, sk) = keygen(64).expect("keygen");
        let x = BigUint::from_bytes_be(&sk.x.to_be_bytes());
        assert!(x >= BigUint::one());
        assert!(x < sk.params.q);
    }

    #[test]
    fn test_keygen_from_params_deterministic_group() {
        let params = generate_group_params(64).expect("params");
        let (pk1, _) = keygen_from_params(&params).expect("keygen1");
        let (pk2, _) = keygen_from_params(&params).expect("keygen2");
        // Same group parameters
        assert_eq!(pk1.params, pk2.params);
        // Different public keys (overwhelmingly likely)
        // — we don't assert inequality since there's a negligible collision probability
    }
}
