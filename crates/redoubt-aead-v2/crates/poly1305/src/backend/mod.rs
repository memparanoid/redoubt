// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The arithmetic, once in Rust and once by hand.
//!
//! Everything that reads a byte of the message or touches a limb is here. What
//! is above holds the storage and says in what order these are called, and
//! that is all it does — the buffering included, because deciding where a
//! block ends means reading the message.
//!
//! Nothing crosses the boundary by value, and nothing is returned. Not a limb,
//! not a byte of key, not the state, and not a length either: every one of them
//! is a pointer to storage the caller declared.
//!
//! The lengths are there for a different reason than the secrets. A returned
//! value leaves in a register, and a register carrying the answer out is a
//! register the wipe at the end of an assembly routine cannot touch. So the
//! answer goes to memory the caller named and every register is free to go.
//!
//! `poly1305_asm` is set by the build script for a target it compiled assembly
//! for, and is named nowhere but the alias below.

pub(crate) mod rust;

#[cfg(poly1305_asm)]
pub(crate) mod asm;

use redoubt_aead_v2_core::Backend;
use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

#[cfg(poly1305_asm)]
use asm as chosen;

#[cfg(not(poly1305_asm))]
use rust as chosen;

use crate::consts::LIMBS;

/// Whether this target was built with assembly, which is what `Auto` goes to.
///
/// Where it is false the two backends are the same code, and a test that finds
/// them agreeing has proved nothing.
#[cfg(any(test, feature = "test-utils"))]
pub const HAS_ASM: bool = cfg!(poly1305_asm);

/// The key split in two: `r` as five clamped limbs, `s` as it arrived.
pub(crate) fn init(
    backend: Backend,
    r: &mut [u32; LIMBS],
    s: &mut [u8; BLOCK_SIZE],
    key: &[u8; KEY_SIZE],
) {
    match backend {
        Backend::Rust => rust::init(r, s, key),
        Backend::Auto => chosen::init(r, s, key),
    }
}

/// As much of the message as the caller has, with `filled` arriving as how far
/// the buffer is used and leaving as how far it is used now.
pub(crate) fn update(
    backend: Backend,
    acc: &mut [u64; LIMBS],
    r: &[u32; LIMBS],
    block: &mut [u8; BLOCK_SIZE],
    filled: &mut usize,
    said: &[u8],
) {
    match backend {
        Backend::Rust => rust::update(acc, r, block, filled, said),
        Backend::Auto => chosen::update(acc, r, block, filled, said),
    }
}

/// What is left of the message, the marker that goes after it, and the tag.
///
/// One call and not a loop the caller drives: a message handed over whole goes
/// through every block of itself without the bytes coming back here in
/// between.
pub(crate) fn finalize(
    backend: Backend,
    acc: &mut [u64; LIMBS],
    r: &[u32; LIMBS],
    s: &[u8; BLOCK_SIZE],
    said: &[u8],
    out: &mut [u8; TAG_SIZE],
) {
    match backend {
        Backend::Rust => rust::finalize(acc, r, s, said, out),
        Backend::Auto => chosen::finalize(acc, r, s, said, out),
    }
}
