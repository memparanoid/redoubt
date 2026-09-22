// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the assembly leaves behind, where there is assembly to ask.

mod probes;

use std::panic::{AssertUnwindSafe, catch_unwind};

use redoubt_aead_core::consts::chacha::{BLOCK_SIZE, KEY_SIZE, NONCE_SIZE};

use crate::backend::asm::xor;

// === === === === === === === === === ===
// xor
// === === === === === === === === === ===

/// The length is handed to the assembly, which reads that many bytes and picks
/// a layout from it, so a width it does not know is undefined rather than
/// wrong. No caller outside this crate reaches it — the entry points take
/// `&[u8; 12]` and `&[u8; 8]`, and the array is erased at this seam only so the
/// two variants share one routine — which leaves the next caller inside it.
#[test]
fn test_xor_rejects_a_nonce_width_the_assembly_cannot_read() {
    for len in 0..=2 * NONCE_SIZE {
        if len == 8 || len == NONCE_SIZE {
            continue;
        }

        let result = catch_unwind(AssertUnwindSafe(|| {
            xor(
                &[0x42; KEY_SIZE],
                &std::vec![0x17; len],
                0,
                &mut [0_u8; BLOCK_SIZE],
            );
        }));

        assert!(result.is_err(), "a nonce of {len} bytes was taken");
    }
}
