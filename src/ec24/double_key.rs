//! Multi-use double-key protocol.
//!
//! Exposes `MultiUseDoubleKey` which ratchets the underlying double key `dk`
//! to allow sending a stream of anamorphic ciphertexts without reusing the
//! exact same PRF key, maintaining security against Chosen Ciphertext Attacks (CCA).

use hmac::{Hmac, KeyInit, Mac};
use core::fmt;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::anamorphic::keygen::DoubleKey;
use crate::ct::{ct_modpow_boxed, ct_scalar_from_bytes_mod_q};
use crate::params::GroupParams;

type HmacSha256 = Hmac<Sha256>;

const RATCHET_EXTRACT_SALT: &[u8] = b"anamorph-ec24-ratchet-extract-v1";
const RATCHET_EXPAND_INFO: &[u8] = b"anamorph-ec24-ratchet-expand-v1";

/// A stateful double key supporting multiple uses via HMAC ratcheting.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MultiUseDoubleKey {
    /// The current double key state.
    pub current_dk: DoubleKey,
    /// A monotonic counter to enforce forward secrecy / domain separation limit.
    pub use_count: u64,
}

impl fmt::Debug for MultiUseDoubleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiUseDoubleKey")
            .field("current_dk", &"<redacted>")
            .field("use_count", &self.use_count)
            .finish()
    }
}

impl MultiUseDoubleKey {
    /// Initialize a new multi-use double key starting from an initial EC22 `DoubleKey`.
    pub fn new(base_dk: DoubleKey) -> Self {
        Self {
            current_dk: base_dk,
            use_count: 0,
        }
    }

    /// Ratchet the double key forward for the next use.
    ///
    /// The new secret exponent is derived using an HKDF-like extract/expand
    /// structure with explicit domain separation and direct scalar reduction.
    /// The structure updates `current_dk.dk` and `current_dk.dk_pub`.
    pub fn ratchet(&mut self, params: &GroupParams) {
        self.use_count += 1;

        let q_byte_len = ((params.q.bits() + 7) / 8) as usize;
        let out_len = q_byte_len.saturating_mul(2).max(1);

        let mut dk_bytes = self.current_dk.dk.to_be_bytes().to_vec();
        let mut derived_bytes = derive_ratchet_bytes(&dk_bytes, self.use_count, out_len);
        let updated_dk = ct_scalar_from_bytes_mod_q(&derived_bytes, &params.q)
            .expect("q must be non-zero and representable");
        derived_bytes.zeroize();
        dk_bytes.zeroize();

        self.current_dk.dk = updated_dk;
        self.current_dk.dk_pub = ct_modpow_boxed(&params.g, &self.current_dk.dk, &params.p)
            .expect("ct_modpow_boxed should not fail on valid params");
    }

    /// Access the current DoubleKey to utilize in EC22 anamorphic modes natively.
    pub fn current_key(&self) -> &DoubleKey {
        &self.current_dk
    }
}

fn derive_ratchet_bytes(ikm: &[u8], use_count: u64, out_len: usize) -> Vec<u8> {
    let mut extract_mac = HmacSha256::new_from_slice(RATCHET_EXTRACT_SALT)
        .expect("HMAC accepts any key length");
    extract_mac.update(ikm);
    let mut prk = extract_mac.finalize().into_bytes();

    let mut okm = Vec::with_capacity(out_len);
    let mut previous_block = Vec::new();
    let use_count_bytes = use_count.to_be_bytes();
    let mut counter = 1u64;

    while okm.len() < out_len {
        let mut expand_mac = HmacSha256::new_from_slice(&prk)
            .expect("HMAC accepts any key length");
        if !previous_block.is_empty() {
            expand_mac.update(&previous_block);
        }
        expand_mac.update(RATCHET_EXPAND_INFO);
        expand_mac.update(&use_count_bytes);
        expand_mac.update(b"dk_update");
        expand_mac.update(&counter.to_be_bytes());

        let block = expand_mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&block);
        previous_block.zeroize();
        previous_block = block;
        counter += 1;
    }

    prk.zeroize();
    previous_block.zeroize();
    okm.truncate(out_len);
    okm
}
