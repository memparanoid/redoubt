// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The encoding and the decoding, once in Rust and once by hand.
//!
//! `hex_asm` is set by the build script for a target it compiled assembly for,
//! and it is named nowhere but the alias below: `Auto` is whatever was chosen
//! for this target.

pub(crate) mod rust;

#[cfg(hex_asm)]
pub(crate) mod asm;

#[cfg(hex_asm)]
use asm as chosen;

#[cfg(not(hex_asm))]
use rust as chosen;

use redoubt_asm::Backend;

/// Whether this target was built with assembly.
#[cfg(all(
    test,
    not(target_os = "windows"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) const HAS_ASM: bool = cfg!(hex_asm);

/// `src` as lowercase hex digits in `dst`, two per byte.
///
/// # Safety
///
/// `dst` twice as long as `src`.
pub(crate) unsafe fn bytes_to_hex(backend: Backend, src: &[u8], dst: &mut [u8]) {
    match backend {
        // SAFETY: the caller's, verbatim.
        Backend::Rust => unsafe { rust::bytes_to_hex(src, dst) },
        // SAFETY: the caller's, verbatim.
        Backend::Auto => unsafe { chosen::bytes_to_hex(src, dst) },
    }
}

/// The bytes the digits in `src` spell, in `dst`, and whether every one of
/// them was a hex digit; `dst` all zeros when not.
///
/// # Safety
///
/// `src` of even length, and `dst` half as long.
pub(crate) unsafe fn hex_to_bytes(backend: Backend, src: &[u8], dst: &mut [u8]) -> bool {
    match backend {
        // SAFETY: the caller's, verbatim.
        Backend::Rust => unsafe { rust::hex_to_bytes(src, dst) },
        // SAFETY: the caller's, verbatim.
        Backend::Auto => unsafe { chosen::hex_to_bytes(src, dst) },
    }
}
