// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The entry points the seam declares, as calls into the assembly.
//!
//! Flat on purpose. What each one does is declare the routine, say why the
//! pointers it hands over are sound, and call it — so a reader asking what the
//! assembly is given can read the whole of the answer here, and a reader asking
//! what it computes goes to the `.S`.
//!
//! The Rust names carry no prefix and the assembly's do: `redoubt_` is what
//! keeps a symbol from being the one a linked C library also calls
//! `sha256_hash`, and a collision there is resolved by the linker without a
//! word to anybody.

#[cfg(test)]
use crate::consts::BLOCK_SIZE;
#[cfg(any(test, feature = "test-utils"))]
use crate::consts::HASH_SIZE;

unsafe extern "C" {
    // The first three are declared only where something reaches them: this
    // crate's tests, and for the hash a crate above's tests through
    // `test-utils`. The assembly defines them in every build — its own
    // routines call them — and what changes here is whether Rust has a name
    // for one.
    #[cfg(test)]
    fn redoubt_sha256_compress_block(h: *mut u32, block: *const u8);

    #[cfg(any(test, feature = "test-utils"))]
    fn redoubt_sha256_hash(msg: *const u8, msg_len: usize, digest: *mut u8);

    #[cfg(test)]
    fn redoubt_hmac_sha256(
        key: *const u8,
        key_len: usize,
        msg: *const u8,
        msg_len: usize,
        mac: *mut u8,
    );

    fn redoubt_hkdf_sha256(
        salt: *const u8,
        salt_len: usize,
        ikm: *const u8,
        ikm_len: usize,
        info: *const u8,
        info_len: usize,
        okm: *mut u8,
        okm_len: usize,
    );
}

/// One block folded into the state somebody else is carrying.
#[cfg(test)]
pub(crate) fn sha256_compress_block(h: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
    // SAFETY: the state is eight words and the block is `BLOCK_SIZE` bytes,
    // which is what the routine reads and writes, and the two are distinct
    // borrows so they cannot overlap.
    unsafe { redoubt_sha256_compress_block(h.as_mut_ptr(), block.as_ptr()) }
}

/// The digest of a message of any length.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn sha256_hash(data: &[u8], out: &mut [u8; HASH_SIZE]) {
    // SAFETY: the message is as long as the length beside it, the destination
    // is `HASH_SIZE` bytes, and a shared borrow and an exclusive one cannot be
    // the same memory.
    unsafe { redoubt_sha256_hash(data.as_ptr(), data.len(), out.as_mut_ptr()) }
}

/// HMAC-SHA256, RFC 2104.
#[cfg(test)]
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; HASH_SIZE]) {
    // SAFETY: each pointer is as long as the length beside it, the destination
    // is `HASH_SIZE` bytes, and the exclusive borrow is neither of the two
    // shared ones.
    unsafe {
        redoubt_hmac_sha256(
            key.as_ptr(),
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
        );
    }
}

/// HKDF-SHA256, RFC 5869: extract and then expand, in one call.
pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    // SAFETY: each pointer is as long as the length beside it, and the
    // exclusive borrow is none of the three shared ones. Whether the output is
    // a length the counter has blocks for is decided above this file.
    unsafe {
        redoubt_hkdf_sha256(
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            info.as_ptr(),
            info.len(),
            okm.as_mut_ptr(),
            okm.len(),
        );
    }
}
