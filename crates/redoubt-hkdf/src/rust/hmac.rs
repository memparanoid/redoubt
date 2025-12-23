// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HMAC-SHA256 implementation per RFC 2104

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizeOnDropSentinel};

use super::sha256::Sha256State;

const BLOCK_LEN: usize = 64;
const HASH_LEN: usize = 32;

/// HMAC-SHA256 state with all intermediate buffers.
///
/// All sensitive data lives in this struct for guaranteed zeroization on drop.
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub(crate) struct HmacSha256State {
    /// K ⊕ ipad (0x36 repeated)
    k_ipad: [u8; BLOCK_LEN],
    /// K ⊕ opad (0x5c repeated)
    k_opad: [u8; BLOCK_LEN],
    /// Key block when key > BLOCK_LEN (hashed key, zero-padded)
    key_block: [u8; BLOCK_LEN],
    /// SHA256 state for inner hash computation
    sha_inner: Sha256State,
    /// SHA256 state for outer hash computation
    sha_outer: Sha256State,
    /// Inner hash result: SHA256(K ⊕ ipad || message)
    inner_hash: [u8; HASH_LEN],

    __sentinel: ZeroizeOnDropSentinel,
}

impl HmacSha256State {
    /// Create new HMAC-SHA256 state
    pub fn new() -> Self {
        Self {
            k_ipad: [0u8; BLOCK_LEN],
            k_opad: [0u8; BLOCK_LEN],
            key_block: [0u8; BLOCK_LEN],
            sha_inner: Sha256State::new(),
            sha_outer: Sha256State::new(),
            inner_hash: [0u8; HASH_LEN],
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// HMAC-SHA256 per RFC 2104
    pub fn sha256(&mut self, key: &[u8], data: &[u8], out: &mut [u8; HASH_LEN]) {
        // Prevent stale-bytes window
        self.key_block.fast_zeroize();

        // Determine effective key length
        let key_len = if key.len() > BLOCK_LEN {
            // Hash key into key_block
            self.sha_inner.reset();
            self.sha_inner.update(key);
            self.sha_inner.finalize(&mut self.inner_hash);
            self.key_block[..HASH_LEN].copy_from_slice(&self.inner_hash);
            self.inner_hash.fast_zeroize();
            HASH_LEN
        } else {
            // Copy key into key_block
            self.key_block[..key.len()].copy_from_slice(key);
            key.len()
        };

        // Initialize pads
        self.k_ipad.fill(0x36);
        self.k_opad.fill(0x5c);
        for i in 0..key_len {
            self.k_ipad[i] ^= self.key_block[i];
            self.k_opad[i] ^= self.key_block[i];
        }

        // Inner hash: SHA256(k_ipad || data)
        self.sha_inner.reset();
        self.sha_inner.update(&self.k_ipad);
        self.sha_inner.update(data);
        self.sha_inner.finalize(&mut self.inner_hash);

        // Outer hash: SHA256(k_opad || inner_hash) -> out
        self.sha_outer.reset();
        self.sha_outer.update(&self.k_opad);
        self.sha_outer.update(&self.inner_hash);
        self.sha_outer.finalize(out);

        // Zeroize HMAC intermediates immediately
        self.k_ipad.fast_zeroize();
        self.k_opad.fast_zeroize();
        self.key_block.fast_zeroize();
        self.inner_hash.fast_zeroize();
    }
}
