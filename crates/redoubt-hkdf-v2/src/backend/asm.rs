// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The four entry points, as calls into the assembly.
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
//!
//! # While there is no assembly
//!
//! Every function below forwards to `rust`. It is the same signature the
//! assembly will be called through, so when the routines land the change is
//! one body each: the `unsafe` block replaces the forward, and nothing above
//! this file moves.

use crate::backend::rust;
use crate::consts::{BLOCK_SIZE, HASH_SIZE};

/// One block folded into the state somebody else is carrying.
pub(crate) fn sha256_compress_block(h: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
    rust::sha256_compress_block(h, block);
}

/// The digest of a message of any length.
pub(crate) fn sha256_hash(data: &[u8], out: &mut [u8; HASH_SIZE]) {
    rust::sha256_hash(data, out);
}

/// HMAC-SHA256, RFC 2104.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; HASH_SIZE]) {
    rust::hmac_sha256(key, data, out);
}

/// HKDF-SHA256, RFC 5869: extract and then expand, in one call.
pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    rust::hkdf_sha256(salt, ikm, info, okm);
}
