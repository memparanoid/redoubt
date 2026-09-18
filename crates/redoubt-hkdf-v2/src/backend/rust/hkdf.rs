// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA256 implementation per RFC 5869

use alloc::vec::Vec;
use redoubt_zero::{FastZeroizable, RedoubtZero};

use super::hmac::HmacSha256State;

const HASH_LEN: usize = 32;

/// HKDF-SHA256 state with all intermediate buffers
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub(crate) struct HkdfSha256State {
    /// HMAC-SHA256 state
    hmac: HmacSha256State,

    /// PRK = HMAC-Hash(salt, IKM) from Extract phase
    prk: [u8; HASH_LEN],

    /// T(i-1) for Expand phase
    t_prev: [u8; HASH_LEN],

    /// T(i) for Expand phase
    t_curr: [u8; HASH_LEN],

    /// Length of valid data in t_prev (0 for T(0))
    t_prev_len: usize,

    /// Buffer for expand message: t_prev || info || counter
    expand_buf: Vec<u8>,

    /// Runtime verification that zeroization happened, for the tests that
    /// read it.
    ///
    /// Gated because it is an `Arc<AtomicBool>` — one heap allocation per
    /// value, in a type whose whole reason for existing is to leave nothing
    /// in memory. Nothing reads it outside this crate's own tests, and the
    /// `RedoubtZero` derive treats the field as optional.
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
}

#[cfg(test)]
impl HkdfSha256State {
    pub(crate) fn unzeroize(&mut self) {
        self.prk.fill(1u8);
    }
}

impl HkdfSha256State {
    /// Create new HKDF state
    pub fn new() -> Self {
        Self {
            hmac: HmacSha256State::new(),
            prk: [0u8; HASH_LEN],
            t_prev: [0u8; HASH_LEN],
            t_curr: [0u8; HASH_LEN],
            t_prev_len: 0,
            expand_buf: Vec::new(),
            #[cfg(test)]
            __sentinel: redoubt_zero::ZeroizeOnDropSentinel::default(),
        }
    }

    /// HKDF-Extract per RFC 5869 Section 2.2
    fn extract(&mut self, salt: &[u8], ikm: &[u8]) {
        const DEFAULT_SALT: [u8; HASH_LEN] = [0u8; HASH_LEN];
        let salt = if salt.is_empty() {
            &DEFAULT_SALT[..]
        } else {
            salt
        };

        self.hmac.sha256(salt, ikm, &mut self.prk);
    }

    /// HKDF-Expand per RFC 5869 Section 2.3
    fn expand(&mut self, info: &[u8], out: &mut [u8]) {
        let out_len = out.len();
        let n = out_len.div_ceil(HASH_LEN);
        let mut offset = 0;

        // T(0) = empty
        self.t_prev_len = 0;

        for i in 1..=n {
            // Build message: t_prev || info || counter
            self.expand_buf.clear();

            if self.t_prev_len > 0 {
                // Not `extend_from_slice`, which is `memcpy` over a length the
                // compiler cannot see, and `t_prev` is the previous block of
                // the derived key.
                //
                // For consistency and not for safety. This is the portable
                // implementation: the compression below moves the same bytes
                // through whichever registers the compiler picked, so closing
                // one copy does not make the rest of it quiet. What it buys is
                // that no secret in this workspace moves by any other copy.
                //
                // The buffer was cleared above, so this writes from its start.
                self.expand_buf.resize(self.t_prev_len, 0);

                // SAFETY: the buffer was just made exactly long enough for the
                // bytes being written, and the two are different allocations.
                unsafe {
                    redoubt_mem::copy_nonoverlapping(
                        self.t_prev.as_ptr(),
                        self.expand_buf.as_mut_ptr(),
                        self.t_prev_len,
                    );
                }
            }

            self.expand_buf.extend_from_slice(info);
            self.expand_buf.push(i as u8);

            // T(i) = HMAC-SHA256(PRK, message)
            self.hmac
                .sha256(&self.prk, &self.expand_buf, &mut self.t_curr);

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

        // Zeroize expand_buf and t_prev
        self.expand_buf.fast_zeroize();
        self.t_prev.fast_zeroize();
    }

    /// Full HKDF: Extract-then-Expand
    pub fn derive(&mut self, ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
        self.extract(salt, ikm);
        self.expand(info, out);
        self.fast_zeroize();
    }
}
