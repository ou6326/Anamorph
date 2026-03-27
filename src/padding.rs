//! Block-padding for length-oracle mitigation (stub).
//!
//! **Owner:** Owen Ouyang — Security Hardening
//!
//! This module will implement block-padding to neutralise ciphertext-length
//! oracles.  Without padding, an observer could distinguish anamorphic
//! ciphertexts from normal ones based on covert payload length.
//!
//! ## Planned API
//!
//! ```ignore
//! let padded = Pkcs7Padding::pad(data, 32);
//! let original = Pkcs7Padding::unpad(&padded)?;
//! ```

/// Trait for block-padding schemes.
///
/// Implementors provide deterministic padding that ensures all ciphertexts
/// have the same length regardless of plaintext size.
pub trait PaddingScheme {
    /// Pad `data` to a multiple of `block_size` bytes.
    fn pad(data: &[u8], block_size: usize) -> Vec<u8>;

    /// Remove padding and return the original data.
    ///
    /// Returns `Err(AnamorphError::PaddingError)` if padding is malformed.
    fn unpad(data: &[u8]) -> crate::errors::Result<Vec<u8>>;
}

// Owen: implement `Pkcs7Padding` or `Iso7816Padding` here.
