//! HMAC-SHA256 integrity layer (stub).
//!
//! **Owner:** Owen Ouyang — Security Hardening
//!
//! This module will provide an integrity root for anamorphic ciphertexts,
//! allowing detection of tampering.  It partially closes the anamorphic-CCA
//! gap identified in recent literature.
//!
//! ## Planned API
//!
//! ```ignore
//! let tag = IntegrityLayer::tag(&key, &ciphertext_bytes);
//! IntegrityLayer::verify(&key, &ciphertext_bytes, &tag)?;
//! ```

/// Trait for ciphertext integrity tagging.
///
/// Implementors provide a MAC-based integrity layer that can be applied
/// to ciphertext bytes before transmission and verified on receipt.
pub trait IntegrityLayer {
    /// The tag type (e.g. `[u8; 32]` for HMAC-SHA256).
    type Tag: AsRef<[u8]>;

    /// Compute an integrity tag over `data` using `key`.
    fn tag(key: &[u8], data: &[u8]) -> Self::Tag;

    /// Verify that `tag` is valid for `data` under `key`.
    ///
    /// Returns `Ok(())` on success, `Err(AnamorphError::IntegrityError)` on failure.
    fn verify(key: &[u8], data: &[u8], tag: &Self::Tag) -> crate::errors::Result<()>;
}

// Owen: implement `HmacSha256Integrity` here.
