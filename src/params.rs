//! Safe-prime generation, generator selection, and group-parameter validation.
//!
//! All ElGamal operations in this crate work in the multiplicative group
//! $Z_p^*$, where $$p = 2q + 1$$ is a safe prime and $g$ generates
//! the order-$q$
//! subgroup.
//!
//! **Owner:** Owen Ouyang - Security Hardening
//!
//! Scope in this module:
//! - Secure parameter generation (safe-prime selection + generator validation).
//! - Group membership validation for all externally provided elements.
//! - CSPRNG-backed parameter sampling via system entropy sources.

use crypto_bigint::{U256, U512, U1024, U2048, U4096, U8192};
use crypto_primes::{random_prime, Flavor};
use getrandom::SysRng;
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::ct::ct_modpow_biguint;
use crate::errors::{AnamorphError, Result};

pub(crate) struct InfallibleSysRng(SysRng);

impl InfallibleSysRng {
    pub(crate) fn new() -> Self {
        Self(SysRng)
    }
}

impl crypto_bigint::rand_core::TryRng for InfallibleSysRng {
    type Error = crypto_bigint::rand_core::Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        match self.0.try_next_u32() {
            Ok(v) => Ok(v),
            Err(_) => panic!("system RNG failure"),
        }
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        match self.0.try_next_u64() {
            Ok(v) => Ok(v),
            Err(_) => panic!("system RNG failure"),
        }
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        match self.0.try_fill_bytes(dst) {
            Ok(()) => Ok(()),
            Err(_) => panic!("system RNG failure"),
        }
    }
}

impl crypto_bigint::rand_core::TryCryptoRng for InfallibleSysRng {}

macro_rules! random_safe_prime_with_width {
    ($ty:ty, $bit_size:expr, $rng:expr) => {{
        let p = random_prime::<$ty, _>($rng, Flavor::Safe, $bit_size);
        BigUint::from_bytes_be(&p.to_be_bytes())
    }};
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parameters defining the cyclic group for ElGamal operations.
///
/// **Invariants** (enforced at construction):
/// - $p$ is a safe prime with $p = 2q + 1$ where $q$ is also prime.
/// - $g$ is a generator of the order-$q$ subgroup of $Z_p^*$.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupParams {
    /// Safe prime modulus.
    pub p: BigUint,
    /// Sophie Germain prime: $q$ such that $p = 2q + 1$.
    pub q: BigUint,
    /// Generator of the order-$q$ subgroup of $Z_p^*$.
    pub g: BigUint,
    /// Bit-length that was requested when generating these parameters.
    pub bit_size: usize,
}

impl GroupParams {
    /// Validate that these parameters form a safe-prime group with a valid
    /// generator for the order-$q$ subgroup.
    pub fn validate(&self) -> Result<()> {
        let one = BigUint::one();

        if self.p <= one || self.q <= one || self.g <= one {
            return Err(AnamorphError::InvalidParameter(
                "group parameters must be greater than 1".to_string(),
            ));
        }

        if self.p != (&self.q << 1u32) + &one {
            return Err(AnamorphError::InvalidParameter(
                "p must satisfy p = 2q + 1".to_string(),
            ));
        }

        if !is_probably_prime(&self.p, 40) || !is_probably_prime(&self.q, 40) {
            return Err(AnamorphError::InvalidParameter(
                "p and q must be prime".to_string(),
            ));
        }

        validate_group_membership(&self.g, &self.p, &self.q)
            .map_err(|_| {
                AnamorphError::InvalidParameter(
                    "g must be a member of the order-q subgroup".to_string(),
                )
            })
    }
}

// ---------------------------------------------------------------------------
// Prime generation
// ---------------------------------------------------------------------------

/// Generate a safe prime $p = 2q + 1$ of `bit_size` bits.
///
/// Uses `crypto-primes` with `Flavor::Safe` to sample $p$ directly,
/// then derives $q = (p - 1) / 2$.
pub fn generate_safe_prime(bit_size: usize) -> Result<(BigUint, BigUint)> {
    if bit_size < 64 {
        return Err(AnamorphError::InvalidParameter(
            "bit size must be at least 64".to_string(),
        ));
    }

    let bit_size = u32::try_from(bit_size).map_err(|_| AnamorphError::PrimeGenerationFailed)?;
    let mut rng = InfallibleSysRng::new();

    let p = match bit_size {
        0..=256 => catch_unwind(AssertUnwindSafe(|| {
            random_safe_prime_with_width!(U256, bit_size, &mut rng)
        }))
        .map_err(|_| AnamorphError::PrimeGenerationFailed)?,
        257..=512 => catch_unwind(AssertUnwindSafe(|| {
            random_safe_prime_with_width!(U512, bit_size, &mut rng)
        }))
        .map_err(|_| AnamorphError::PrimeGenerationFailed)?,
        513..=1024 => catch_unwind(AssertUnwindSafe(|| {
            random_safe_prime_with_width!(U1024, bit_size, &mut rng)
        }))
        .map_err(|_| AnamorphError::PrimeGenerationFailed)?,
        1025..=2048 => catch_unwind(AssertUnwindSafe(|| {
            random_safe_prime_with_width!(U2048, bit_size, &mut rng)
        }))
        .map_err(|_| AnamorphError::PrimeGenerationFailed)?,
        2049..=4096 => catch_unwind(AssertUnwindSafe(|| {
            random_safe_prime_with_width!(U4096, bit_size, &mut rng)
        }))
        .map_err(|_| AnamorphError::PrimeGenerationFailed)?,
        4097..=8192 => catch_unwind(AssertUnwindSafe(|| {
            random_safe_prime_with_width!(U8192, bit_size, &mut rng)
        }))
        .map_err(|_| AnamorphError::PrimeGenerationFailed)?,
        _ => return Err(AnamorphError::PrimeGenerationFailed),
    };

    let q = (&p - BigUint::one()) >> 1u32;
    Ok((p, q))
}

/// Generate full group parameters: safe prime + generator.
pub fn generate_group_params(bit_size: usize) -> Result<GroupParams> {
    let (p, q) = generate_safe_prime(bit_size)?;
    let g = find_generator(&p, &q)?;
    let params = GroupParams {
        p,
        q,
        g,
        bit_size,
    };

    params.validate()?;
    Ok(params)
}

// ---------------------------------------------------------------------------
// Generator selection
// ---------------------------------------------------------------------------

/// Find a generator of the order-q subgroup of $Z_p^*$.
///
/// Find a generator of the order-$q$ subgroup of $Z_p^*$.
///
/// For a safe prime $p = 2q + 1$, the subgroup of order $q$ in $Z_p^*$ consists
/// of the quadratic residues $(\bmod p)$.
///
/// This function samples $h$ uniformly from $Z_p^*$ and sets $g = h^2 \pmod{p}$,
/// so $g$ is guaranteed to lie in the order-$q$ subgroup. Since $q$ is prime, any
/// non-identity element has order $q$; therefore checking $g \neq 1$ suffices for
/// $g$ to be a generator of that subgroup.
pub fn find_generator(p: &BigUint, q: &BigUint) -> Result<BigUint> {
    let mut rng = rand::thread_rng();
    let one = BigUint::one();
    let p_minus_one = p - &one;

    for _ in 0..1_000 {
        let h = rng.gen_biguint_range(&BigUint::from(2u32), &p_minus_one);

        // Compute $g = h^2 \pmod{p}$ to guarantee $g$ is in the order-$q$ subgroup.
        let g = ct_modpow_biguint(&h, &BigUint::from(2u32), p)?;

        // Reject the identity element.
        if g == one {
            continue;
        }

        // Verify: $g^q \equiv 1 \pmod{p}$.
        debug_assert!(
            ct_modpow_biguint(&g, q, p)
                .map(|v| v == one)
                .unwrap_or(false),
            "generator check failed"
        );

        return Ok(g);
    }

    Err(AnamorphError::InvalidParameter(
        "failed to find a subgroup generator".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Group membership
// ---------------------------------------------------------------------------

/// Validate that `element` is a member of the order-q subgroup of Z_p^*.
///
/// Validate that `element` is a member of the order-$q$ subgroup of $Z_p^*$.
///
/// Returns `Ok(())` if $1 < \text{element} < p$ and $\text{element}^q \equiv 1 \pmod{p}$.
pub fn validate_group_membership(
    element: &BigUint,
    p: &BigUint,
    q: &BigUint,
) -> Result<()> {
    let one = BigUint::one();

    if element <= &one || element >= p {
        return Err(AnamorphError::GroupMembershipError);
    }

    if ct_modpow_biguint(element, q, p)? != one {
        return Err(AnamorphError::GroupMembershipError);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Miller-Rabin primality test
// ---------------------------------------------------------------------------

/// Probabilistic Miller-Rabin primality test with k rounds.
///
/// Probabilistic Miller-Rabin primality test with $k$ rounds.
///
/// Error probability is at most $4^{-k}$ for $k \geq 1$.
/// Returns `false` when $k = 0$.
pub fn is_probably_prime(n: &BigUint, k: u32) -> bool {
    let one = BigUint::one();

    if k == 0 || n <= &one {
        return false;
    }
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    if n == &two || n == &three {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write $n - 1 = 2^s \cdot d$ where $d$ is odd.
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s: u32 = 0;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    let mut rng = rand::thread_rng();

    'witness: for _ in 0..k {
        // Pick random a in [2, n-2].
        let a = if n > &BigUint::from(4u32) {
            rng.gen_biguint_range(&two, &n_minus_one)
        } else {
            two.clone()
        };

        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_one {
            continue 'witness;
        }

        for _ in 0..s.saturating_sub(1) {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'witness;
            }
        }

        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// First 100 small primes for trial-division sieving.
#[cfg(test)]
fn small_primes_list() -> Vec<u64> {
    vec![
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
        67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
        139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
        223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
        383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
        463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::ct_modpow_biguint;
    use num_traits::Zero;

    #[test]
    fn test_small_primes_are_prime() {
        for &sp in &small_primes_list() {
            assert!(
                is_probably_prime(&BigUint::from(sp), 20),
                "{sp} should be prime"
            );
        }
    }

    #[test]
    fn test_miller_rabin_composites() {
        let composites = [4u64, 6, 8, 9, 10, 15, 21, 25, 100, 1000];
        for &c in &composites {
            assert!(
                !is_probably_prime(&BigUint::from(c), 20),
                "{c} should be composite"
            );
        }
    }

    #[test]
    fn test_miller_rabin_zero_rounds_are_rejected() {
        assert!(!is_probably_prime(&BigUint::from(9u32), 0));
        assert!(!is_probably_prime(&BigUint::from(13u32), 0));
    }

    #[test]
    fn test_generate_safe_prime_64bit() {
        let (p, q) = generate_safe_prime(64).expect("safe prime generation");
        // Verify $p = 2q + 1$
        assert_eq!(p, &q * 2u32 + 1u32);
        // Verify both are prime
        assert!(is_probably_prime(&p, 40));
        assert!(is_probably_prime(&q, 40));
    }

    #[test]
    fn test_find_generator() {
        let (p, q) = generate_safe_prime(64).expect("safe prime generation");
        let g = find_generator(&p, &q).expect("generator");
        // g^q ≡ 1 (mod p)
        assert_eq!(ct_modpow_biguint(&g, &q, &p).expect("modpow"), BigUint::one());
        // g != 1
        assert_ne!(g, BigUint::one());
    }

    #[test]
    fn test_group_membership_valid() {
        let (p, q) = generate_safe_prime(64).expect("safe prime");
        let g = find_generator(&p, &q).expect("generator");
        assert!(validate_group_membership(&g, &p, &q).is_ok());
    }

    #[test]
    fn test_group_membership_invalid() {
        let (p, q) = generate_safe_prime(64).expect("safe prime");
        // 0 is not in the group
        assert!(validate_group_membership(&BigUint::zero(), &p, &q).is_err());
        // 1 is the identity, our check requires > 1
        assert!(validate_group_membership(&BigUint::one(), &p, &q).is_err());
        // p is not in [1, p)
        assert!(validate_group_membership(&p, &p, &q).is_err());
    }
}
