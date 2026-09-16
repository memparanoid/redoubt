// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The assembly, declared once for everything below that calls it raw.
//!
//! Elsewhere in this tree a `mod.rs` is declarations only; here a second copy
//! of seven signatures would be a second thing to get wrong. Production first,
//! in the order the assembly declares them, then the probe, which nothing in
//! production calls.

mod support;

mod aegis128l;
mod asm;
mod probes;
mod rfc;
mod wycheproof;

use redoubt_aead_v2_core::consts::aegis::{KEY_SIZE, NONCE_SIZE};

unsafe extern "C" {
    pub(crate) fn redoubt_aegis128l_encrypt(
        key: *const u8,
        nonce: *const u8,
        aad: *const u8,
        aad_len: usize,
        data: *mut u8,
        data_len: usize,
        tag: *mut u8,
    );
    pub(crate) fn redoubt_aegis128l_decrypt(
        key: *const u8,
        nonce: *const u8,
        aad: *const u8,
        aad_len: usize,
        data: *mut u8,
        data_len: usize,
        tag: *mut u8,
    );

    // The probe, last and apart: what asks first, then what is asked about.
    pub(crate) fn redoubt_aegis128l_registers_are_zeroized() -> u64;
    pub(crate) fn redoubt_aegis128l_frame_is_zeroized() -> u64;
    pub(crate) fn redoubt_aegis128l_dirty_registers();
    pub(crate) fn redoubt_aegis128l_dirty_frame(at: usize);
    pub(crate) fn redoubt_aegis128l_clean_frame();
}

/// The frame every routine takes, as the layout at the top of the assembly
/// declares it.
pub(crate) const FRAME: usize = 32;

/// A key and a nonce at the widths the routines read.
///
/// Their values are arbitrary: nothing that uses them asserts on an answer.
pub(crate) fn material() -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    (
        core::array::from_fn(|at| 0x40 + at as u8),
        core::array::from_fn(|at| 0x70 + at as u8),
    )
}
