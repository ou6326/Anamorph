//! Constant-time helpers (stub).
//!
//! **Owner:** Owen Ouyang — Security Hardening
//!
//! This module re-exports types from the [`subtle`] crate and will
//! provide constant-time wrappers for all secret-dependent operations
//! in the crate (comparisons, conditional selection, etc.).
//!
//! The goal is to prevent timing side-channels in all code paths that
//! handle secret keys, ephemeral exponents, or double-key material.

// Re-export subtle types for use throughout the crate.
pub use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time comparison of two byte slices.
///
/// Returns `true` iff the slices are equal, in constant time.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// Owen: add constant-time conditional selection, BigUint wrappers, etc.
