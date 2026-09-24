// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead::Aead;
use redoubt_forensics::AnyError;
use redoubt_vault::leak_master_key;

/// The secret: thirty-two bytes, none repeated, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping the sweep does not read and is never
/// found as a copy of itself.
pub(crate) const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// The needle, built from its last byte to its first and never turned around:
/// the forward bytes must not exist in this process, even for as long as a
/// reversal takes.
pub(crate) fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// How much of the master key a box encrypts with: the default cipher's key.
pub(crate) fn master_key_width() -> usize {
    Aead::default().key_size()
}

/// The key needle, opened once and turned around where it lies: what is held
/// from then on is the key backwards, which is not the key.
pub(crate) fn master_key_backwards() -> Result<Vec<u8>, AnyError> {
    let mut needle = leak_master_key(master_key_width())?;

    needle.reverse();

    Ok(needle.to_vec())
}
