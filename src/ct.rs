//! Constant-time helpers for secret-dependent arithmetic.
//!
//! This module keeps the private-exponent Montgomery ladder / modular
//! exponentiation path constant-time with respect to the exponent.
//! It does not make the full protocol constant-time: callers still use
//! variable-time `BigUint` conversions, serialization, and some public
//! comparisons at higher layers.
//!
//! **Owner:** Owen Ouyang — Security Hardening
//!
//! This module wraps core operations from the `subtle` crate to keep secret-
//! dependent branching out of higher-level code.

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    NonZero,
    BoxedUint,
    CtSelect,
};
use num_bigint::BigUint;
use num_traits::One;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::errors::{AnamorphError, Result};

/// Constant-time comparison of two byte slices.
///
/// Returns `Choice(1)` when equal, otherwise `Choice(0)`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    let max_len = a.len().max(b.len());
    let mut a_padded = vec![0u8; max_len];
    let mut b_padded = vec![0u8; max_len];

    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);

    // Length equality is part of byte-string equality semantics; without this,
    // zero-prefix collisions like [0x00, 0x01] vs [0x01] would compare equal.
    let same_len = Choice::from((a.len() == b.len()) as u8);
    let out = same_len & a_padded.ct_eq(&b_padded);

    a_padded.zeroize();
    b_padded.zeroize();

    out
}

/// Constant-time comparison of two byte slices as a `bool`.
pub fn ct_eq_bool(a: &[u8], b: &[u8]) -> bool {
    bool::from(ct_eq(a, b))
}

/// Constant-time comparison for big integers with fixed-width encoding.
///
/// The caller provides `width` (in bytes), typically derived from the modulus
/// size, so both values are compared on equal-length encodings.
///
/// Note: this helper still performs length-dependent host operations before the
/// constant-time equality primitive (e.g., byte conversion and bounded copies).
/// Callers should only use it when operand byte-length leakage is acceptable or
/// when inputs are already guaranteed to fit `width`.
pub fn ct_eq_biguint_fixed(a: &BigUint, b: &BigUint, width: usize) -> Choice {
    let mut a_bytes = a.to_bytes_be();
    let mut b_bytes = b.to_bytes_be();
    let mut valid = Choice::from((a_bytes.len() <= width) as u8);
    valid &= Choice::from((b_bytes.len() <= width) as u8);

    let mut a_fixed = vec![0u8; width];
    let mut b_fixed = vec![0u8; width];

    if a_bytes.len() <= width {
        let a_off = width - a_bytes.len();
        a_fixed[a_off..].copy_from_slice(&a_bytes);
    }
    a_bytes.zeroize();

    if b_bytes.len() <= width {
        let b_off = width - b_bytes.len();
        b_fixed[b_off..].copy_from_slice(&b_bytes);
    }
    b_bytes.zeroize();

    let out = valid & a_fixed.ct_eq(&b_fixed);

    a_fixed.zeroize();
    b_fixed.zeroize();

    out
}

/// Modular exponentiation using runtime Montgomery parameters.
///
/// The exponent is re-encoded to the modulus byte-width before entering the
/// constant-time Montgomery path, so the Montgomery computation sees a fixed-size input.
/// The surrounding `BigUint` conversion is still variable-time.
pub fn ct_modpow_biguint(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> Result<BigUint> {
    let mut result = ct_modpow_biguint_to_boxed(base, exponent, modulus)?;
    Ok(boxed_uint_to_biguint(&mut result))
}

/// Constant-time modular exponentiation using Montgomery parameters.
///
/// Accepts a `BoxedUint` exponent and performs constant-time modular
/// exponentiation with respect to the exponent. Both the modulus and exponent
/// are normalized to fixed-width before the Montgomery ladder runs.
/// The final conversion back to `BigUint` uses a variable-time byte trim for
/// interoperability with existing call sites.
pub fn ct_modpow_boxed(base: &BigUint, exponent: &BoxedUint, modulus: &BigUint) -> Result<BigUint> {
    let mut result = ct_modpow_boxed_to_boxed(base, exponent, modulus)?;
    Ok(boxed_uint_to_biguint(&mut result))
}

/// Constant-time modular exponentiation returning a zeroizable boxed integer.
pub fn ct_modpow_biguint_to_boxed(
    base: &BigUint,
    exponent: &BigUint,
    modulus: &BigUint,
) -> Result<BoxedUint> {
    let width = ((modulus.bits() as usize + 7) / 8).max(1);
    let mut exp = boxed_uint_from_biguint_fixed(exponent, width)?;
    let result = ct_modpow_boxed_to_boxed(base, &exp, modulus);
    exp.zeroize();
    result
}

/// Constant-time modular exponentiation returning a zeroizable boxed integer.
pub fn ct_modpow_boxed_to_boxed(
    base: &BigUint,
    exponent: &BoxedUint,
    modulus: &BigUint,
) -> Result<BoxedUint> {
    let width = ((modulus.bits() as usize + 7) / 8).max(1);
    let mut mod_boxed = boxed_uint_from_biguint_fixed(modulus, width)?;
    let mod_odd = Option::from(mod_boxed.to_odd())
        .ok_or_else(|| AnamorphError::InvalidParameter("modulus must be odd".to_string()))?;
    let params = BoxedMontyParams::new(mod_odd);

    // Re-normalize caller-provided exponent to modulus width to keep
    // Montgomery ladder iterations fixed for this modulus size.
    let mut exp_bytes = exponent.to_be_bytes();
    let mut exp_normalized = boxed_uint_from_be_bytes_fixed(&exp_bytes, width)?;
    exp_bytes.zeroize();

    let base_boxed = boxed_uint_from_biguint_fixed(base, width)?;
    let out = BoxedMontyForm::new(base_boxed, &params)
        .pow(&exp_normalized)
        .retrieve();
    exp_normalized.zeroize();
    mod_boxed.zeroize();

    Ok(out)
}

/// Constant-time modular multiplication: `(a * b) mod modulus`.
///
/// Converts the inputs to fixed-width wide integers and performs the
/// multiplication and reduction in constant time with respect to the
/// values of `a` and `b`. The surrounding `BigUint` conversions are
/// variable-time.
pub fn ct_mul_mod_biguint(a: &BigUint, b: &BigUint, modulus: &BigUint) -> Result<BigUint> {
    let mut result = ct_mul_mod_biguint_to_boxed(a, b, modulus)?;
    Ok(boxed_uint_to_biguint(&mut result))
}

/// Constant-time modular multiplication returning a zeroizable boxed integer.
pub fn ct_mul_mod_biguint_to_boxed(
    a: &BigUint,
    b: &BigUint,
    modulus: &BigUint,
) -> Result<BoxedUint> {
    let width = ((modulus.bits() as usize + 7) / 8).max(1);

    let mut a_boxed = boxed_uint_from_biguint_fixed(a, width)?;
    let mut b_boxed = boxed_uint_from_biguint_fixed(b, width)?;
    let mut mod_boxed = boxed_uint_from_biguint_fixed(modulus, width)?;

    // Keep a single representation under explicit zeroization control.
    // Using Montgomery forms here would introduce internal copies that this
    // function cannot explicitly zeroize today.
    let mod_nz = NonZero::new(mod_boxed.clone())
        .ok_or_else(|| AnamorphError::InvalidParameter("modulus must be non-zero".to_string()))?;
    let result_boxed = a_boxed.mul_mod(&b_boxed, &mod_nz);

    a_boxed.zeroize();
    b_boxed.zeroize();
    mod_boxed.zeroize();

    Ok(result_boxed)
}

/// Derive a scalar in `[1, q-1]` directly from bytes.
///
/// This avoids the `bytes -> BigUint -> mod -> bytes` chain for secret-derived
/// material. Input is normalized to a fixed-width wide integer, reduced modulo
/// `q`, then maps zero to one to guarantee output in `[1, q-1]`.
pub fn ct_scalar_from_bytes_mod_q(bytes: &[u8], q: &BigUint) -> Result<BoxedUint> {
    if *q <= BigUint::one() {
        return Err(AnamorphError::InvalidParameter("q must be > 1".to_string()));
    }
    if bytes.is_empty() {
        return Err(AnamorphError::InvalidParameter(
            "scalar input bytes must be non-empty".to_string(),
        ));
    }

    let q_width = ((q.bits() + 7) / 8) as usize;
    // Allocate enough width for the full input plus one byte so reductions
    // don't silently drop high-order input bytes.
    let wide_width = q_width
        .saturating_mul(2)
        .max(bytes.len().saturating_add(1))
        .max(1);
    let wide_bits = (wide_width as u32) * 8;

    // Fixed-width ingest over the full input byte string.
    let mut wide_fixed = vec![0u8; wide_width];
    let copy_len = bytes.len();
    wide_fixed[wide_width - copy_len..].copy_from_slice(bytes);

    let mut wide = BoxedUint::from_be_slice(&wide_fixed, wide_bits)
        .map_err(|_| AnamorphError::InvalidParameter("invalid scalar input bytes".to_string()))?;
    wide_fixed.zeroize();

    let q_boxed = boxed_uint_from_biguint_fixed(q, wide_width)?;
    let q_nz = NonZero::new(q_boxed)
        .ok_or_else(|| AnamorphError::InvalidParameter("q must be non-zero".to_string()))?;

    let mut reduced = wide.rem(&q_nz);
    wide.zeroize();
    let one = BoxedUint::one_with_precision(wide_bits);
    let mut mapped = reduced.ct_select(&one, reduced.is_zero());
    reduced.zeroize();

    // Return with q's native precision for downstream modular exponentiation paths.
    let mut mapped_bytes = mapped.to_be_bytes();
    let mapped_len = mapped_bytes.len();
    // `mapped_len` is deterministic for a fixed `wide_bits` precision.
    let start = mapped_len.saturating_sub(q_width);
    let out = boxed_uint_from_be_bytes_fixed(&mapped_bytes[start..], q_width)?;
    mapped_bytes.zeroize();
    mapped.zeroize();

    Ok(out)
}

fn boxed_uint_to_biguint(value: &mut BoxedUint) -> BigUint {
    let mut bytes = value.to_be_bytes();
    let result = BigUint::from_bytes_be(&bytes);
    bytes.zeroize();
    value.zeroize();
    result
}

/// Convert a `BigUint` into a fixed-width `BoxedUint` using big-endian bytes.
///
/// This helper zero-pads values shorter than `width` and rejects values that
/// would overflow the target width.
fn boxed_uint_from_biguint_fixed(value: &BigUint, width: usize) -> Result<BoxedUint> {
    let mut bytes = value.to_bytes_be();
    let out = boxed_uint_from_be_bytes_fixed(&bytes, width);
    bytes.zeroize();
    out
}

/// Convert a big-endian byte slice into a fixed-width `BoxedUint`.
///
/// The input is left-padded with zeros to `width` bytes, and the conversion
/// fails if the value would not fit in that width.
fn boxed_uint_from_be_bytes_fixed(bytes: &[u8], width: usize) -> Result<BoxedUint> {
    if bytes.len() > width {
        return Err(AnamorphError::InvalidParameter(
            "value does not fit in fixed width".to_string(),
        ));
    }

    let mut fixed = vec![0u8; width];
    let offset = width - bytes.len();
    fixed[offset..].copy_from_slice(&bytes);

    let bits_precision = (width as u32) * 8;
    let out = BoxedUint::from_be_slice(&fixed, bits_precision)
        .map_err(|_| AnamorphError::InvalidParameter("invalid fixed-width value".to_string()))?;

    fixed.zeroize();
    Ok(out)
}
