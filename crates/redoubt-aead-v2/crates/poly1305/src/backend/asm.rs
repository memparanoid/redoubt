// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The arithmetic by hand, where a target has it.

use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

use crate::consts::LIMBS;

pub(crate) fn init(r: &mut [u32; LIMBS], s: &mut [u8; BLOCK_SIZE], key: &[u8; KEY_SIZE]) {
    super::rust::init(r, s, key);
}

pub(crate) fn update(
    acc: &mut [u64; LIMBS],
    r: &[u32; LIMBS],
    block: &mut [u8; BLOCK_SIZE],
    filled: &mut usize,
    said: &[u8],
) {
    super::rust::update(acc, r, block, filled, said);
}

pub(crate) fn finalize(
    acc: &mut [u64; LIMBS],
    r: &[u32; LIMBS],
    s: &[u8; BLOCK_SIZE],
    said: &[u8],
    out: &mut [u8; TAG_SIZE],
) {
    super::rust::finalize(acc, r, s, said, out);
}
