// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The rounds, once in Rust and once by hand.
//!
//! Everything that reads a byte of the key or touches a word of the state is
//! here. What is above says which of these is called and in what order, and
//! that is all it does.
//!
//! Nothing crosses the boundary by value and nothing is returned. A returned
//! value leaves in a register, and a register carrying the answer out is a
//! register the wipe at the end of an assembly routine cannot touch.
//!
//! The whole buffer goes to [`xor`] in one call, not a block at a time. A seam
//! of one block is a seam that cannot process four of them at once, which is
//! where the speed of every vectorized implementation lives — and where this
//! one would have to give it up for good.
//!
//! `chacha_asm` is set by the build script for a target it compiled assembly
//! for, and is named nowhere but the alias below.

pub(crate) mod rust;

#[cfg(chacha_asm)]
pub(crate) mod asm;

use redoubt_aead_v2_core::consts::chacha::{HNONCE_SIZE, KEY_SIZE, XNONCE_SIZE};
use redoubt_asm::Backend;

#[cfg(chacha_asm)]
use asm as chosen;

#[cfg(not(chacha_asm))]
use rust as chosen;

#[cfg(test)]
use crate::consts::WORDS;

/// Whether this target was built with assembly, which is what `Auto` goes to.
///
/// Where it is false the two backends are the same code, and a test that finds
/// them agreeing has proved nothing.
#[cfg(any(test, feature = "test-utils"))]
pub const HAS_ASM: bool = cfg!(chacha_asm);

/// The twenty rounds, on a state somebody else built.
///
/// Reachable on its own for the one published answer that is an intermediate:
/// RFC 8439 §2.3.2 prints the state after the rounds and before it is added
/// back, which nothing that returns a keystream can be held to.
#[cfg(test)]
pub(crate) fn rounds(backend: Backend, state: &mut [u32; WORDS]) {
    match backend {
        Backend::Rust => rust::rounds(state),
        Backend::Auto => chosen::rounds(state),
    }
}

/// The subkey a twenty-four byte nonce derives, HChaCha20.
pub(crate) fn subkey(
    backend: Backend,
    out: &mut [u8; KEY_SIZE],
    key: &[u8; KEY_SIZE],
    nonce: &[u8; HNONCE_SIZE],
) {
    match backend {
        Backend::Rust => rust::subkey(out, key, nonce),
        Backend::Auto => chosen::subkey(out, key, nonce),
    }
}

/// `data` xored with the keystream that starts at `counter`.
///
/// The nonce says which variant this is: twelve bytes is RFC 8439 with a
/// counter of thirty-two bits, and eight is Bernstein's original with a counter
/// of sixty-four.
pub(crate) fn xor(
    backend: Backend,
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    counter: u64,
    data: &mut [u8],
) {
    match backend {
        Backend::Rust => rust::xor(key, nonce, counter, data),
        Backend::Auto => chosen::xor(key, nonce, counter, data),
    }
}

/// The same, under the subkey a twenty-four byte nonce derives.
///
/// One operation and not two, so that the subkey is made and used without ever
/// coming back across this boundary.
pub(crate) fn xxor(
    backend: Backend,
    key: &[u8; KEY_SIZE],
    nonce: &[u8; XNONCE_SIZE],
    counter: u64,
    data: &mut [u8],
) {
    match backend {
        Backend::Rust => rust::xxor(key, nonce, counter, data),
        Backend::Auto => chosen::xxor(key, nonce, counter, data),
    }
}
