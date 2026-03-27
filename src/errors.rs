use std::fmt;

/// Errors produced by the anamorph cryptographic library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnamorphError {
    /// A supplied parameter (prime, generator, key) is invalid.
    InvalidParameter(String),

    /// Decryption failed (e.g. ciphertext not in the group).
    DecryptionFailed(String),

    /// An element failed the group-membership check (element^q ≢ 1 mod p).
    GroupMembershipError,

    /// Block-padding is malformed or cannot be removed.
    PaddingError(String),

    /// HMAC integrity check failed — possible tampering.
    IntegrityError,

    /// The message is too large to encode as a group element.
    MessageTooLarge,

    /// Prime generation did not converge within the iteration budget.
    PrimeGenerationFailed,
}

impl fmt::Display for AnamorphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {msg}"),
            Self::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            Self::GroupMembershipError => write!(f, "element is not a member of the group"),
            Self::PaddingError(msg) => write!(f, "padding error: {msg}"),
            Self::IntegrityError => write!(f, "integrity check failed"),
            Self::MessageTooLarge => write!(f, "message too large to encode as group element"),
            Self::PrimeGenerationFailed => write!(f, "safe prime generation failed"),
        }
    }
}

impl std::error::Error for AnamorphError {}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, AnamorphError>;
