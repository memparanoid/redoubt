// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The rounds by hand, where a target has them.

use redoubt_aead_v2_core::consts::chacha::{
    BLOCK_SIZE, HNONCE_SIZE, KEY_SIZE, NONCE_SIZE, XNONCE_SIZE,
};

#[cfg(test)]
use crate::consts::WORDS;

unsafe extern "C" {
    #[cfg(test)]
    fn redoubt_chacha_rounds(state: *mut u32);
    fn redoubt_hchacha_subkey(out: *mut u8, key: *const u8, nonce: *const u8);
    fn redoubt_chacha_xor(
        key: *const u8,
        nonce: *const u8,
        counter: u64,
        data: *mut u8,
        len: usize,
        nonce_len: usize,
    );
    fn redoubt_xchacha_xor(
        key: *const u8,
        nonce: *const u8,
        counter: u64,
        data: *mut u8,
        len: usize,
    );
}

#[cfg(test)]
pub(crate) fn rounds(state: &mut [u32; WORDS]) {
    // SAFETY: the exclusive reference names sixteen initialized, writable words.
    unsafe { redoubt_chacha_rounds(state.as_mut_ptr()) };
}

pub(crate) fn subkey(out: &mut [u8; KEY_SIZE], key: &[u8; KEY_SIZE], nonce: &[u8; HNONCE_SIZE]) {
    // SAFETY: the arrays have the exact sizes the assembly reads and writes.
    // The exclusive output cannot overlap either shared input.
    unsafe { redoubt_hchacha_subkey(out.as_mut_ptr(), key.as_ptr(), nonce.as_ptr()) };
}

pub(crate) fn xor(key: &[u8; KEY_SIZE], nonce: &[u8], counter: u64, data: &mut [u8]) {
    assert!(
        nonce.len() == 8 || nonce.len() == NONCE_SIZE,
        "invalid ChaCha20 nonce length"
    );
    let last = if nonce.len() == NONCE_SIZE {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    };

    check_counter(counter, last, data.len());

    // SAFETY: the nonce layout and counter range were checked above; the key
    // and data references cover every accessed byte and do not overlap.
    unsafe {
        redoubt_chacha_xor(
            key.as_ptr(),
            nonce.as_ptr(),
            counter,
            data.as_mut_ptr(),
            data.len(),
            nonce.len(),
        );
    }
}

pub(crate) fn xxor(key: &[u8; KEY_SIZE], nonce: &[u8; XNONCE_SIZE], counter: u64, data: &mut [u8]) {
    check_counter(counter, u64::from(u32::MAX), data.len());

    // SAFETY: the arrays have the required lengths, the counter cannot wrap,
    // and data is exclusive. The subkey is made and used inside this call.
    unsafe {
        redoubt_xchacha_xor(
            key.as_ptr(),
            nonce.as_ptr(),
            counter,
            data.as_mut_ptr(),
            data.len(),
        );
    }
}

/// Reject an exhausted counter before assembly reads a secret or writes data.
fn check_counter(counter: u64, last: u64, len: usize) {
    let blocks = len.div_ceil(BLOCK_SIZE) as u64;

    assert!(
        counter <= last && (blocks == 0 || blocks - 1 <= last - counter),
        "the message runs past the end of the counter"
    );
}
