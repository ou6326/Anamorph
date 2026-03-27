//! Normal-mode ElGamal: `Gen`, `Enc`, `Dec`.
//!
//! This module implements standard ElGamal public-key encryption over
//! the order-`q` subgroup of Z*_p where `p = 2q + 1` is a safe prime.

pub mod keygen;
pub mod encrypt;
pub mod decrypt;

pub use keygen::{keygen, PublicKey, SecretKey};
pub use encrypt::{encrypt, Ciphertext};
pub use decrypt::decrypt;
