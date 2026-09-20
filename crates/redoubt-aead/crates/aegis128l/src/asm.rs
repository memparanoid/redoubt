// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The two routines the assembly exports.
//!
//! Nothing crosses by value except the two lengths, and nothing is returned. A
//! returned value leaves in a register, and a register carrying the answer out
//! is one the wipe at the end of a routine cannot touch.
//!
//! [`decrypt`] does not compare. It writes the tag the message it was given
//! deserves, and whether that equals the one that arrived is settled in
//! constant time by whoever called this.

use redoubt_aead_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};

#[cfg(aegis128l_asm)]
unsafe extern "C" {
    fn redoubt_aegis128l_encrypt(
        key: *const u8,
        nonce: *const u8,
        aad: *const u8,
        aad_len: usize,
        data: *mut u8,
        data_len: usize,
        tag: *mut u8,
    );
    fn redoubt_aegis128l_decrypt(
        key: *const u8,
        nonce: *const u8,
        aad: *const u8,
        aad_len: usize,
        data: *mut u8,
        data_len: usize,
        tag: *mut u8,
    );
}

/// What a call reaches where the build script compiled nothing.
#[cfg(not(aegis128l_asm))]
fn unbuilt() -> ! {
    panic!("AEGIS-128L has no assembly on this target: ask HAS_ASM before calling")
}

/// `data` enciphered where it lies, and the tag that authenticates it and the
/// AAD together.
#[cfg(not(aegis128l_asm))]
pub(crate) fn encrypt(
    _key: &[u8; KEY_SIZE],
    _nonce: &[u8; NONCE_SIZE],
    _aad: &[u8],
    _data: &mut [u8],
    _tag: &mut [u8; TAG_SIZE],
) {
    unbuilt()
}

/// `data` deciphered where it lies, and the tag it would have had.
#[cfg(not(aegis128l_asm))]
pub(crate) fn decrypt(
    _key: &[u8; KEY_SIZE],
    _nonce: &[u8; NONCE_SIZE],
    _aad: &[u8],
    _data: &mut [u8],
    _tag: &mut [u8; TAG_SIZE],
) {
    unbuilt()
}

/// `data` enciphered where it lies, and the tag that authenticates it and the
/// AAD together.
#[cfg(aegis128l_asm)]
pub(crate) fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    data: &mut [u8],
    tag: &mut [u8; TAG_SIZE],
) {
    // SAFETY: the three arrays are the exact widths the routine reads and
    // writes, which is what their types guarantee, and the exclusive
    // references cannot overlap the shared ones.
    unsafe {
        redoubt_aegis128l_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            aad.as_ptr(),
            aad.len(),
            data.as_mut_ptr(),
            data.len(),
            tag.as_mut_ptr(),
        );
    }
}

/// `data` deciphered where it lies, and the tag it would have had.
///
/// The caller compares. Until it has, what this leaves in `data` is a plaintext
/// nothing has vouched for.
#[cfg(aegis128l_asm)]
pub(crate) fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    data: &mut [u8],
    tag: &mut [u8; TAG_SIZE],
) {
    // SAFETY: as above. The routine writes the tag it computed rather than
    // reading one, so `tag` is exclusive here for the same reason.
    unsafe {
        redoubt_aegis128l_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            aad.as_ptr(),
            aad.len(),
            data.as_mut_ptr(),
            data.len(),
            tag.as_mut_ptr(),
        );
    }
}
