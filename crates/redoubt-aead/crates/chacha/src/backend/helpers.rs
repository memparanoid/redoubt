// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What both backends have to agree on before either touches a key.

use redoubt_aead_core::consts::chacha::{BLOCK_SIZE, NONCE_SIZE};

/// The highest counter a nonce of this width leaves room for.
///
/// Twelve bytes is RFC 8439, where the counter is thirty-two bits; anything
/// else is Bernstein's original, where it is sixty-four.
pub(crate) fn last_counter(nonce_len: usize) -> u64 {
    if nonce_len == NONCE_SIZE {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    }
}

/// Reject an exhausted counter before a backend reads a secret or writes data.
///
/// A counter that wraps hands out a keystream that was already used, so what
/// this refuses is two messages under one stretch of it.
pub(crate) fn check_counter(counter: u64, last: u64, len: usize) {
    let blocks = len.div_ceil(BLOCK_SIZE) as u64;

    assert!(
        counter <= last && (blocks == 0 || blocks - 1 <= last - counter),
        "the message runs past the end of the counter"
    );
}
