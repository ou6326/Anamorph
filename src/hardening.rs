//! Low-level cryptographic hardening primitives.
//!
//! This module is intentionally kept separate from higher-level flows (for
//! example, encryption/decryption APIs) so that MAC generation/verification logic
//! lives in one audited place.
//!
//! **Owner:** Owen Ouyang - Security Hardening
//!
//! Responsibilities covered with adjacent modules:
//! - Constant-time critical paths (via `crate::ct`).
//! - HMAC-SHA256 integrity enforcement (via `generate_mac` and `verify_mac`).
//! - Block-padding layer support (via `crate::padding`).
//! - CCA vulnerability surface analysis and oracle-risk reduction.
//!
//! ## Why a dedicated module?
//! - Keeps low-level primitives reusable and testable.
//! - Avoids duplicating HMAC logic across normal/anamorphic paths.
//! - Makes security review easier by narrowing where tag checks happen.
//!
//! Use this module directly as the single MAC entry point.
//!
//! # Examples
//! ```rust
//! use anamorph::hardening::{generate_mac, verify_mac};
//!
//! let key = b"integrity-key-16";
//! let data = b"ciphertext-bytes";
//! let tag = generate_mac(key, data).expect("mac");
//! assert!(verify_mac(key, data, &tag).is_ok());
//! ```
//!
//! ```rust
//! use anamorph::hardening::{generate_mac, verify_mac};
//! use anamorph::errors::AnamorphError;
//!
//! let key = b"integrity-key-16";
//! let mut data = b"ciphertext-bytes".to_vec();
//! let tag = generate_mac(key, &data).expect("mac");
//! data[0] ^= 0x01;
//! assert_eq!(verify_mac(key, &data, &tag), Err(AnamorphError::IntegrityError));
//! ```

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::errors::{AnamorphError, Result};

/// Type alias for HMAC-SHA256.
pub type HmacSha256 = Hmac<Sha256>;

/// Authentication tag size in bytes (SHA-256 output length).
pub const MAC_SIZE: usize = 32;

/// Generates an HMAC-SHA256 authentication tag for `data` using `key`.
///
/// # Arguments
///
/// - `key` — HMAC key (must be at least 16 bytes for cryptographic security)
/// - `data` — input data to authenticate
///
/// # Errors
///
/// Returns `AnamorphError::IntegrityError` if key validation fails (including minimum length).
/// Returns `AnamorphError::IntegrityError` for internal HMAC failures.
pub fn generate_mac(key: &[u8], data: &[u8]) -> Result<[u8; MAC_SIZE]> {
    if key.len() < 16 {
        return Err(AnamorphError::IntegrityError);
    }

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| AnamorphError::IntegrityError)?;
    mac.update(data);

    let mut result = mac.finalize().into_bytes().to_vec();
    let mut tag = [0u8; MAC_SIZE];
    tag.copy_from_slice(&result);
    result.zeroize();
    Ok(tag)
}

/// Verifies an HMAC-SHA256 tag in constant time.
///
/// Returns `Ok(())` on successful verification, `Err(AnamorphError::IntegrityError)`
/// on tag mismatch or key validation failure.
///
/// # Arguments
///
/// - `key` — HMAC key (must be at least 16 bytes)
/// - `data` — input data to verify
/// - `expected_tag` — authentication tag to verify against
///
/// # Implementation
///
/// Internally this uses `Mac::verify_slice`, which performs constant-time
/// verification for valid tag lengths. All failures (including invalid key length)
/// return `IntegrityError` to provide a uniform error type and prevent timing side-channels.
pub fn verify_mac(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()> {
    if key.len() < 16 {
           return Err(AnamorphError::IntegrityError);
    }

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| AnamorphError::IntegrityError)?;
    mac.update(data);
    mac.verify_slice(expected_tag)
        .map_err(|_| AnamorphError::IntegrityError)
}