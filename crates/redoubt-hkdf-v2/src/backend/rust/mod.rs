// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA256 in Rust, and the four entry points the seam above calls.
//!
//! A directory rather than a file because the parts are four and each is a
//! standard of its own: the word and its six functions, the compression FIPS
//! 180-4 defines over it, the authenticator of RFC 2104, and the derivation of
//! RFC 5869. They stack, and a reader following one of them wants the file it
//! is in and not the three it is not.
//!
//! The four below are what this module exports, and they are the same four
//! `asm` exports with the same signatures. That is what lets a test ask each of
//! them of either implementation, and what makes the seam above a `match` and
//! nothing else.

pub(crate) mod hkdf;
pub(crate) mod hmac;
pub(crate) mod sha256;
pub(crate) mod word32;

#[cfg(test)]
use crate::consts::{BLOCK_SIZE, HASH_SIZE};

use hkdf::HkdfSha256State;
#[cfg(test)]
use hmac::HmacSha256State;
#[cfg(test)]
use sha256::Sha256State;

/// One block folded into the state somebody else is carrying.
///
/// Reachable on its own because it is the one step of SHA-256 that has
/// published answers of its own, and because the assembly has a symbol for it.
#[cfg(test)]
pub(crate) fn sha256_compress_block(h: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
    let mut state = Sha256State::new();

    state.compress_block(h, block);
}

/// The digest of a message of any length.
#[cfg(test)]
pub(crate) fn sha256_hash(data: &[u8], out: &mut [u8; HASH_SIZE]) {
    let mut state = Sha256State::new();

    state.hash(data, out);
}

/// HMAC-SHA256, RFC 2104.
#[cfg(test)]
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; HASH_SIZE]) {
    let mut state = HmacSha256State::new();

    state.sha256(key, data, out);
}

/// HKDF-SHA256, RFC 5869: extract and then expand, in one call.
///
/// Takes no refusal of its own. Whether the output is a length there are blocks
/// for is decided above, where it can be answered once for both
/// implementations.
pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    let mut state = HkdfSha256State::new();

    state.derive(ikm, salt, info, okm);
}
