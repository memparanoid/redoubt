// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
pub const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A needle, built from its last byte to its first.
///
/// Copied and turned over in place through `redoubt-mem`, which empties the
/// registers it uses: the compiler's own reverse loads the value forwards into
/// a vector register sixteen bytes at a time, and a photograph that spills the
/// registers finds them there.
pub fn backwards(of: &[u8]) -> Vec<u8> {
    let mut reversed = vec![0_u8; of.len()];

    // SAFETY: `reversed` was made as long as `of`, and the two are different
    // allocations.
    unsafe { redoubt_mem_core::copy_nonoverlapping(of.as_ptr(), reversed.as_mut_ptr(), of.len()) };

    let half = reversed.len() / 2;
    let (front, back) = reversed.split_at_mut(half);

    for (first, last) in front.iter_mut().zip(back.iter_mut().rev()) {
        redoubt_mem_core::swap(first, last);
    }

    reversed
}
