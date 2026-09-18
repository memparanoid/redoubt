// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The four operations, once in Rust and once by hand.
//!
//! Everything that reads a byte of the key or touches a word of the state is
//! below here. What is above says which of these is called and refuses what
//! cannot be answered, and that is all it does.
//!
//! Nothing crosses the boundary by value and nothing is returned. A returned
//! value leaves in a register, and a register carrying the answer out is a
//! register the wipe at the end of an assembly routine cannot touch. The
//! lengths that do cross are public: how long a message is says nothing about
//! what is in it.
//!
//! `hkdf_asm` is set by the build script for a target it compiled assembly for,
//! and is named nowhere but the alias below. Written a second time — a
//! `target_arch` list here beside a different list in the build script — is how
//! a target ends up with the alias pointing one way and the symbols compiled
//! the other.

pub(crate) mod rust;

#[cfg(hkdf_asm)]
pub(crate) mod asm;

use redoubt_asm::Backend;

use crate::consts::{BLOCK_SIZE, HASH_SIZE};

#[cfg(hkdf_asm)]
use asm as chosen;

#[cfg(not(hkdf_asm))]
use rust as chosen;

/// Whether this target was built with assembly, which is what `Auto` goes to.
///
/// Where it is false the two backends are the same code, and a test that finds
/// them agreeing has proved nothing.
#[cfg(test)]
pub(crate) const HAS_ASM: bool = cfg!(hkdf_asm);

/// One block folded into the state somebody else is carrying.
pub(crate) fn sha256_compress_block(backend: Backend, h: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
    match backend {
        Backend::Rust => rust::sha256_compress_block(h, block),
        Backend::Auto => chosen::sha256_compress_block(h, block),
    }
}

/// The digest of a message of any length.
pub(crate) fn sha256_hash(backend: Backend, data: &[u8], out: &mut [u8; HASH_SIZE]) {
    match backend {
        Backend::Rust => rust::sha256_hash(data, out),
        Backend::Auto => chosen::sha256_hash(data, out),
    }
}

/// HMAC-SHA256, RFC 2104.
pub(crate) fn hmac_sha256(backend: Backend, key: &[u8], data: &[u8], out: &mut [u8; HASH_SIZE]) {
    match backend {
        Backend::Rust => rust::hmac_sha256(key, data, out),
        Backend::Auto => chosen::hmac_sha256(key, data, out),
    }
}

/// HKDF-SHA256, RFC 5869: extract and then expand, in one call.
///
/// One operation and not two, so that the pseudorandom key extract produces is
/// made and used without ever coming back across this boundary.
pub(crate) fn hkdf_sha256(backend: Backend, salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    match backend {
        Backend::Rust => rust::hkdf_sha256(salt, ikm, info, okm),
        Backend::Auto => chosen::hkdf_sha256(salt, ikm, info, okm),
    }
}
