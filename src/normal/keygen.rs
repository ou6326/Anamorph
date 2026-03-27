//! ElGamal key generation — `Gen(λ)`.
//!
//! Produces a public key `(params, h = g^x mod p)` and a secret key `x`,
//! where `x` is uniformly random in `[1, q-1]`.

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::thread_rng;

use crate::errors::Result;
use crate::params::{generate_group_params, GroupParams};

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
/// **Security note:** `x` should be zeroized after use.  Owen's hardening
/// phase will add `#[derive(Zeroize, ZeroizeOnDrop)]`.
#[derive(Debug, Clone)]
pub struct SecretKey {
    /// Underlying group parameters (p, q, g).
    pub params: GroupParams,
    /// Secret exponent in `[1, q-1]`.
    pub x: BigUint,
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
    let mut rng = thread_rng();
    let one = BigUint::one();

    // x ← [1, q-1]
    let x = rng.gen_biguint_range(&one, &params.q);

    // h = g^x mod p
    let h = params.g.modpow(&x, &params.p);

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
        assert!(sk.x >= BigUint::one());
        assert!(sk.x < sk.params.q);
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
