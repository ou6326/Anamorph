//! Safe-prime generation, generator selection, and group-parameter validation.
//!
//! All ElGamal operations in this crate work in the multiplicative group
//! Z*_p where p = 2q + 1 is a safe prime and g generates the order-q
//! subgroup.

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;

use crate::errors::{AnamorphError, Result};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parameters defining the cyclic group for ElGamal operations.
///
/// **Invariants** (enforced at construction):
/// - `p` is a safe prime: `p = 2q + 1` where `q` is also prime.
/// - `g` is a generator of the order-`q` subgroup of Z*_p.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupParams {
    /// Safe prime modulus.
    pub p: BigUint,
    /// Sophie Germain prime (p = 2q + 1).
    pub q: BigUint,
    /// Generator of the order-q subgroup of Z*_p.
    pub g: BigUint,
    /// Bit-length that was requested when generating these parameters.
    pub bit_size: usize,
}

// ---------------------------------------------------------------------------
// Prime generation
// ---------------------------------------------------------------------------

/// Generate a safe prime `p = 2q + 1` of `bit_size` bits.
///
/// Both `p` and `q` are verified with the Miller-Rabin primality test
/// using 40 rounds (error probability ≤ 2⁻⁸⁰).
///
/// # Panics
/// Panics if `bit_size < 64`.
pub fn generate_safe_prime(bit_size: usize) -> Result<(BigUint, BigUint)> {
    assert!(bit_size >= 64, "bit_size must be at least 64");

    let mut rng = thread_rng();
    let one = BigUint::one();
    let two = &one + &one;

    // Trial-division sieve for small factors — speeds up candidate rejection.
    let small_primes: Vec<u64> = small_primes_list();

    for _ in 0..100_000 {
        // Generate a random odd number of the requested bit length.
        let q_candidate = rng.gen_biguint((bit_size - 1) as u64) | &one;

        // Quick trial-division reject.
        if small_primes
            .iter()
            .any(|&sp| (&q_candidate % sp).is_zero() && q_candidate != BigUint::from(sp))
        {
            continue;
        }

        // Miller-Rabin on q.
        if !is_probably_prime(&q_candidate, 40) {
            continue;
        }

        let p_candidate = &q_candidate * &two + &one;

        // Miller-Rabin on p.
        if is_probably_prime(&p_candidate, 40) {
            return Ok((p_candidate, q_candidate));
        }
    }

    Err(AnamorphError::PrimeGenerationFailed)
}

/// Generate full group parameters: safe prime + generator.
pub fn generate_group_params(bit_size: usize) -> Result<GroupParams> {
    let (p, q) = generate_safe_prime(bit_size)?;
    let g = find_generator(&p, &q)?;
    Ok(GroupParams {
        p,
        q,
        g,
        bit_size,
    })
}

// ---------------------------------------------------------------------------
// Generator selection
// ---------------------------------------------------------------------------

/// Find a generator of the order-`q` subgroup of Z*_p.
///
/// For a safe prime `p = 2q + 1` the subgroup of order `q` in Z*_p
/// consists of the quadratic residues mod `p`.  A random element `h` of
/// Z*_p is a generator of this subgroup iff `h² ≢ 1 (mod p)` and
/// `h^q ≡ 1 (mod p)` (equivalently, `h ≠ ±1 mod p`).
pub fn find_generator(p: &BigUint, q: &BigUint) -> Result<BigUint> {
    let mut rng = thread_rng();
    let one = BigUint::one();
    let p_minus_one = p - &one;

    for _ in 0..1_000 {
        let h = rng.gen_biguint_range(&BigUint::from(2u32), &p_minus_one);

        // Compute g = h^2 mod p to guarantee g is in the order-q subgroup.
        let g = h.modpow(&BigUint::from(2u32), p);

        // Reject the identity element.
        if g == one {
            continue;
        }

        // Verify: g^q ≡ 1 (mod p).
        debug_assert!(g.modpow(q, p) == one, "generator check failed");

        return Ok(g);
    }

    Err(AnamorphError::InvalidParameter(
        "could not find a generator".into(),
    ))
}

// ---------------------------------------------------------------------------
// Group membership
// ---------------------------------------------------------------------------

/// Validate that `element` is a member of the order-`q` subgroup of Z*_p.
///
/// Returns `Ok(())` if `1 < element < p` and `element^q ≡ 1 (mod p)`.
pub fn validate_group_membership(
    element: &BigUint,
    p: &BigUint,
    q: &BigUint,
) -> Result<()> {
    let one = BigUint::one();

    if element <= &one || element >= p {
        return Err(AnamorphError::GroupMembershipError);
    }

    if element.modpow(q, p) != one {
        return Err(AnamorphError::GroupMembershipError);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Miller-Rabin primality test
// ---------------------------------------------------------------------------

/// Probabilistic Miller-Rabin primality test with `k` rounds.
///
/// Error probability ≤ 4^{-k}.
pub fn is_probably_prime(n: &BigUint, k: u32) -> bool {
    let _zero = BigUint::zero();
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);

    if n <= &one {
        return false;
    }
    if n == &two || n == &three {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n - 1 = 2^s * d with d odd.
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s: u64 = 0;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    let mut rng = thread_rng();

    'witness: for _ in 0..k {
        // Pick random a in [2, n-2].
        let a = if n > &BigUint::from(4u32) {
            rng.gen_biguint_range(&two, &(&n_minus_one))
        } else {
            two.clone()
        };

        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_one {
            continue 'witness;
        }

        for _ in 0..s - 1 {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'witness;
            }
        }

        return false; // composite
    }

    true // probably prime
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// First 100 small primes for trial-division sieving.
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
    fn test_generate_safe_prime_64bit() {
        let (p, q) = generate_safe_prime(64).expect("safe prime generation");
        // Verify p = 2q + 1
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
        assert_eq!(g.modpow(&q, &p), BigUint::one());
        // g ≠ 1
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
