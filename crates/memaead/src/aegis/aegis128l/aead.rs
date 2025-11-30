// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L AEAD implementation.
//!
//! All sensitive state is zeroized on drop using memzer.

use memutil::constant_time_eq;
use memzer::{DropSentinel, MemZer};
use zeroize::Zeroize;

use crate::{Aead, DecryptError};

use super::consts::{Aegis128LKey, Aegis128LNonce, Aegis128LTag, BLOCK_SIZE, TAG_SIZE};
use super::state::Aegis128LState;

/// AEGIS-128L AEAD with guaranteed zeroization.
#[derive(Zeroize, MemZer)]
#[zeroize(drop)]
pub struct Aegis128L {
    state: Aegis128LState,
    expected_tag: [u8; TAG_SIZE],
    __drop_sentinel: DropSentinel,
}

impl Default for Aegis128L {
    fn default() -> Self {
        Self {
            state: Aegis128LState::default(),
            expected_tag: [0; TAG_SIZE],
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl core::fmt::Debug for Aegis128L {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Aegis128L {{ [protected] }}")
    }
}

impl Aegis128L {
    /// Process associated data (zero-padded to 32-byte blocks).
    ///
    /// # Safety
    /// Caller must ensure AES hardware support is available.
    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn process_aad(&mut self, aad: &[u8]) {
        let mut offset = 0;
        let full_blocks = aad.len() / BLOCK_SIZE;

        // Process full blocks
        for _ in 0..full_blocks {
            let block: &[u8; 32] = aad[offset..offset + BLOCK_SIZE].try_into().unwrap();
            unsafe { self.state.absorb(block) };
            offset += BLOCK_SIZE;
        }

        // Process partial block (if any)
        let remaining = aad.len() % BLOCK_SIZE;
        if remaining > 0 {
            let block_tmp = self.state.block_tmp();
            block_tmp[..remaining].copy_from_slice(&aad[offset..]);
            block_tmp[remaining..].fill(0);
            let block: [u8; 32] = *block_tmp;
            unsafe { self.state.absorb(&block) };
        }
    }
}

impl Aead for Aegis128L {
    type Key = Aegis128LKey;
    type Nonce = Aegis128LNonce;
    type Tag = Aegis128LTag;

    fn encrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) {
        // Check AES support at runtime
        #[cfg(target_arch = "aarch64")]
        if !std::arch::is_aarch64_feature_detected!("aes") {
            panic!("AES hardware support required");
        }
        #[cfg(target_arch = "x86_64")]
        if !std::arch::is_x86_feature_detected!("aes") {
            panic!("AES hardware support required");
        }

        unsafe { self.encrypt_inner(key, nonce, aad, data, tag) }
    }

    fn decrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), DecryptError> {
        // Check AES support at runtime
        #[cfg(target_arch = "aarch64")]
        if !std::arch::is_aarch64_feature_detected!("aes") {
            panic!("AES hardware support required");
        }
        #[cfg(target_arch = "x86_64")]
        if !std::arch::is_x86_feature_detected!("aes") {
            panic!("AES hardware support required");
        }

        unsafe { self.decrypt_inner(key, nonce, aad, data, tag) }
    }
}

impl Aegis128L {
    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn encrypt_inner(
        &mut self,
        key: &Aegis128LKey,
        nonce: &Aegis128LNonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Aegis128LTag,
    ) {
        let msg_len = data.len();

        // Initialize state
        unsafe { self.state.init(key, nonce) };

        // Process AAD
        unsafe { self.process_aad(aad) };

        // Encrypt full blocks
        let mut offset = 0;
        let full_blocks = msg_len / BLOCK_SIZE;

        for _ in 0..full_blocks {
            let block: &mut [u8; 32] = (&mut data[offset..offset + BLOCK_SIZE]).try_into().unwrap();
            unsafe { self.state.enc(block) };
            offset += BLOCK_SIZE;
        }

        // Encrypt partial block (if any)
        let remaining = msg_len % BLOCK_SIZE;
        if remaining > 0 {
            let block_tmp = self.state.block_tmp();
            block_tmp[..remaining].copy_from_slice(&data[offset..]);
            unsafe { self.state.enc_partial(remaining) };
            data[offset..].copy_from_slice(&self.state.block_tmp()[..remaining]);
        }

        // Finalize and get tag
        unsafe { self.state.finalize(aad.len(), msg_len, tag) };
    }

    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn decrypt_inner(
        &mut self,
        key: &Aegis128LKey,
        nonce: &Aegis128LNonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Aegis128LTag,
    ) -> Result<(), DecryptError> {
        let ct_len = data.len();

        // Initialize state
        unsafe { self.state.init(key, nonce) };

        // Process AAD
        unsafe { self.process_aad(aad) };

        // Decrypt full blocks
        let mut offset = 0;
        let full_blocks = ct_len / BLOCK_SIZE;

        for _ in 0..full_blocks {
            let block: &mut [u8; 32] = (&mut data[offset..offset + BLOCK_SIZE]).try_into().unwrap();
            unsafe { self.state.dec(block) };
            offset += BLOCK_SIZE;
        }

        // Decrypt partial block (if any)
        let remaining = ct_len % BLOCK_SIZE;
        if remaining > 0 {
            let block_tmp = self.state.block_tmp();
            block_tmp[..remaining].copy_from_slice(&data[offset..]);
            unsafe { self.state.dec_partial(remaining) };
            data[offset..].copy_from_slice(&self.state.block_tmp()[..remaining]);
        }

        // Finalize and verify tag
        unsafe { self.state.finalize(aad.len(), ct_len, &mut self.expected_tag) };

        if !constant_time_eq(&self.expected_tag, tag) {
            data.zeroize();
            self.expected_tag.zeroize();
            return Err(DecryptError::AuthenticationFailed);
        }

        self.expected_tag.zeroize();
        Ok(())
    }
}
