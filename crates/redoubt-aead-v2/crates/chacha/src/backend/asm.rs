// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The rounds by hand, where a target has them.

use redoubt_aead_v2_core::consts::chacha::{HNONCE_SIZE, KEY_SIZE, XNONCE_SIZE};

use crate::consts::WORDS;

#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn rounds(state: &mut [u32; WORDS]) {
    super::rust::rounds(state);
}

pub(crate) fn subkey(out: &mut [u8; KEY_SIZE], key: &[u8; KEY_SIZE], nonce: &[u8; HNONCE_SIZE]) {
    super::rust::subkey(out, key, nonce);
}

pub(crate) fn xor(key: &[u8; KEY_SIZE], nonce: &[u8], counter: u64, data: &mut [u8]) {
    super::rust::xor(key, nonce, counter, data);
}

pub(crate) fn xxor(key: &[u8; KEY_SIZE], nonce: &[u8; XNONCE_SIZE], counter: u64, data: &mut [u8]) {
    super::rust::xxor(key, nonce, counter, data);
}
