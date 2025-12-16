// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA512 implementation per RFC 5869
//!
//! All intermediate buffers live in HkdfState for guaranteed zeroization.

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizeOnDropSentinel};

use super::consts::{BLOCK_LEN, HASH_LEN, MAX_OUTPUT_LEN};
use super::error::HkdfError;
use super::sha512::Sha512State;

/// HKDF-SHA512 state with all intermediate buffers.
///
/// All sensitive data lives in this struct for guaranteed zeroization on drop.
/// No stack allocations for sensitive data.
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub(crate) struct HkdfState {
    // ═══════════════════════════════════════════════════════════════════════════
    // HMAC-SHA512 buffers per RFC 6234 Section 8
    // ═══════════════════════════════════════════════════════════════════════════
    /// K ⊕ ipad (0x36 repeated)
    k_ipad: [u8; BLOCK_LEN],
    /// K ⊕ opad (0x5c repeated)
    k_opad: [u8; BLOCK_LEN],
    /// Key block when key > BLOCK_LEN (hashed key, zero-padded)
    key_block: [u8; BLOCK_LEN],
    /// Inner hash result: SHA512(K ⊕ ipad || message)
    inner_hash: [u8; HASH_LEN],

    // ═══════════════════════════════════════════════════════════════════════════
    // HKDF buffers per RFC 5869
    // ═══════════════════════════════════════════════════════════════════════════
    /// PRK = HMAC-Hash(salt, IKM) from Extract phase
    prk: [u8; HASH_LEN],
    /// T(i-1) for Expand phase
    t_prev: [u8; HASH_LEN],
    /// T(i) for Expand phase
    t_curr: [u8; HASH_LEN],
    /// Length of valid data in t_prev (0 for T(0))
    t_prev_len: usize,

    /// ZeroizeOnDropSentinel for zeroization verification
    __sentinel: ZeroizeOnDropSentinel,
}

impl HkdfState {
    /// Create new HKDF state
    pub fn new() -> Self {
        Self {
            k_ipad: [0u8; BLOCK_LEN],
            k_opad: [0u8; BLOCK_LEN],
            key_block: [0u8; BLOCK_LEN],
            inner_hash: [0u8; HASH_LEN],
            prk: [0u8; HASH_LEN],
            t_prev: [0u8; HASH_LEN],
            t_curr: [0u8; HASH_LEN],
            t_prev_len: 0,
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// HMAC-SHA512 for expand phase using prk as key, output to t_curr
    fn hmac_sha512_expand(&mut self, info: &[u8], counter: u8) {
        // PRK is always HASH_LEN (64 bytes), fits in block
        // Initialize pads from prk directly
        self.k_ipad.fill(0x36);
        self.k_opad.fill(0x5c);
        for i in 0..HASH_LEN {
            self.k_ipad[i] ^= self.prk[i];
            self.k_opad[i] ^= self.prk[i];
        }

        // Inner hash: SHA512(k_ipad || t_prev || info || counter)
        {
            let mut sha = Sha512State::new();
            sha.update(&self.k_ipad);
            sha.update(&self.t_prev[..self.t_prev_len]);
            sha.update(info);
            sha.update(&[counter]);
            sha.finalize(&mut self.inner_hash);
        }

        // Outer hash: SHA512(k_opad || inner_hash)
        {
            let mut sha = Sha512State::new();
            sha.update(&self.k_opad);
            sha.update(&self.inner_hash);
            sha.finalize(&mut self.t_curr);
        }

        // Zeroize HMAC intermediates immediately
        self.k_ipad.fast_zeroize();
        self.k_opad.fast_zeroize();
        self.inner_hash.fast_zeroize();
    }

    /// HMAC-SHA512 for extract phase, output directly to prk
    fn hmac_sha512_extract(&mut self, salt: &[u8], ikm: &[u8]) {
        // Determine effective key (salt) length
        let key_len = if salt.len() > BLOCK_LEN {
            // Hash salt into key_block
            let mut sha = Sha512State::new();
            sha.update(salt);
            sha.finalize(
                (&mut self.key_block[..HASH_LEN])
                    .try_into()
                    .expect("Failed to convert slice"),
            );
            HASH_LEN
        } else {
            // Copy salt into key_block
            self.key_block[..salt.len()].copy_from_slice(salt);
            salt.len()
        };

        // Initialize pads
        self.k_ipad.fill(0x36);
        self.k_opad.fill(0x5c);
        for i in 0..key_len {
            self.k_ipad[i] ^= self.key_block[i];
            self.k_opad[i] ^= self.key_block[i];
        }

        // Inner hash: SHA512(k_ipad || ikm)
        {
            let mut sha = Sha512State::new();
            sha.update(&self.k_ipad);
            sha.update(ikm);
            sha.finalize(&mut self.inner_hash);
        }

        // Outer hash: SHA512(k_opad || inner_hash) -> prk
        {
            let mut sha = Sha512State::new();
            sha.update(&self.k_opad);
            sha.update(&self.inner_hash);
            sha.finalize(&mut self.prk);
        }

        // Zeroize HMAC intermediates immediately
        self.k_ipad.fast_zeroize();
        self.k_opad.fast_zeroize();
        self.key_block.fast_zeroize();
        self.inner_hash.fast_zeroize();
    }

    /// HKDF-Extract per RFC 5869 Section 2.2
    ///
    /// PRK = HMAC-Hash(salt, IKM)
    fn extract(&mut self, salt: &[u8], ikm: &[u8]) {
        const DEFAULT_SALT: [u8; HASH_LEN] = [0u8; HASH_LEN];
        let salt = if salt.is_empty() {
            &DEFAULT_SALT[..]
        } else {
            salt
        };
        self.hmac_sha512_extract(salt, ikm);
    }

    /// HKDF-Expand per RFC 5869 Section 2.3
    fn expand(&mut self, info: &[u8], out: &mut [u8]) -> Result<(), HkdfError> {
        let out_len = out.len();

        if out_len > MAX_OUTPUT_LEN {
            return Err(HkdfError::OutputTooLong);
        }

        if out_len == 0 {
            return Ok(());
        }

        let n = (out_len + HASH_LEN - 1) / HASH_LEN;
        let mut offset = 0;

        // T(0) = empty
        self.t_prev_len = 0;

        for i in 1..=n {
            // T(i) = HMAC-SHA512(PRK, T(i-1) || info || i)
            self.hmac_sha512_expand(info, i as u8);

            // Copy to output
            let copy_len = core::cmp::min(HASH_LEN, out_len - offset);
            out[offset..offset + copy_len].copy_from_slice(&self.t_curr[..copy_len]);
            offset += copy_len;

            // T(i-1) = T(i) for next iteration
            self.t_prev.copy_from_slice(&self.t_curr);
            self.t_prev_len = HASH_LEN;

            // Zeroize t_curr
            self.t_curr.fast_zeroize();
        }

        // Zeroize t_prev
        self.t_prev.fast_zeroize();

        Ok(())
    }

    /// Full HKDF: Extract-then-Expand
    pub fn derive(
        &mut self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), HkdfError> {
        self.extract(salt, ikm);
        let result = self.expand(info, out);
        self.prk.fast_zeroize();
        result
    }
}

/// HKDF-SHA512: Extract-then-Expand per RFC 5869
///
/// Derives `out.len()` bytes from input keying material.
///
/// # Arguments
/// * `ikm` - Input keying material (secret)
/// * `salt` - Optional salt (can be empty, will use zeros)
/// * `info` - Optional context/application info
/// * `out` - Output buffer for derived key material
///
/// # Errors
/// Returns `HkdfError::OutputTooLong` if `out.len() > 16320` (255 * 64)
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), HkdfError> {
    let mut state = HkdfState::new();
    state.derive(ikm, salt, info, out)
    // state dropped here, MemZer zeroizes all fields
}
