//! # Project Anamorph
//!
//! The first open Rust implementation of the **Unsynchronized Robustly
//! Anamorphic ElGamal** scheme (EUROCRYPT 2022, extended by EUROCRYPT 2024).
//!
//! ## Modules
//!
//! - [`normal`]  — Standard ElGamal: `Gen`, `Enc`, `Dec`
//! - [`anamorphic`] — Anamorphic ElGamal (EC22): `aGen`, `aEnc`, `aDec`
//! - [`params`]  — Safe-prime generation & group-parameter validation
//! - [`errors`]  — Unified error types
//! - [`integrity`] — (stub) HMAC-SHA256 integrity layer
//! - [`padding`]  — (stub) Block-padding for length-oracle mitigation
//! - [`ct`]       — (stub) Constant-time helpers

pub mod errors;
pub mod params;

pub mod normal;
pub mod anamorphic;

// Stubs for other team members' contributions
pub mod integrity;
pub mod padding;
pub mod ct;
