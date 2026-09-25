// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The standard library's copy and swap, and a UTF-8 check read one byte at a
//! time: the same answers, and no promise about the registers they went
//! through.

/// `bytes` from `src` to `dst`.
///
/// # Safety
///
/// `src` readable and `dst` writable for `bytes`, and the two ranges disjoint.
pub unsafe fn copy_nonoverlapping(src: *const u8, dst: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, bytes) };
}

/// `bytes` exchanged between `a` and `b`.
///
/// # Safety
///
/// `a` and `b` readable and writable for `bytes`, and the two ranges disjoint.
pub unsafe fn swap_nonoverlapping(a: *mut u8, b: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { core::ptr::swap_nonoverlapping(a, b, bytes) };
}

/// Whether `bytes` spell UTF-8, by RFC 3629, reading each byte on its own.
///
/// Not `core::str::from_utf8`, whose fast path reads the text a word at a time
/// and leaves it in registers nothing empties. Every read here is volatile and
/// one byte wide, so the compiler cannot join them into a wider load or
/// vectorise the loop: what a register can be left holding is one byte.
#[inline(never)]
pub fn is_utf8(bytes: &[u8]) -> bool {
    let len = bytes.len();

    let byte = |at: usize| -> u8 {
        // SAFETY: every caller below keeps `at` under `len`, inside the slice.
        unsafe { bytes.as_ptr().add(at).read_volatile() }
    };

    let mut at = 0;

    while at < len {
        let lead = byte(at);

        let width = match lead {
            0x00..=0x7F => 1,
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return false,
        };

        if len - at < width {
            return false;
        }

        if width > 1 {
            // E0 is followed by A0..BF, ED by 80..9F, F0 by 90..BF, F4 by
            // 80..8F, and every other lead by 80..BF.
            let (lowest, highest) = match lead {
                0xE0 => (0xA0, 0xBF),
                0xED => (0x80, 0x9F),
                0xF0 => (0x90, 0xBF),
                0xF4 => (0x80, 0x8F),
                _ => (0x80, 0xBF),
            };

            let second = byte(at + 1);

            if second < lowest || second > highest {
                return false;
            }

            for rest in 2..width {
                if byte(at + rest).wrapping_sub(0x80) > 0x3F {
                    return false;
                }
            }
        }

        at += width;
    }

    true
}

/// Whether every one of `bytes` is zero, reading each byte on its own.
///
/// Volatile and one byte wide, so the compiler cannot widen or vectorise the
/// loads: what a register can be left holding is one byte, and the fold, which
/// is none of them.
#[inline(never)]
pub fn is_zeroized(bytes: &[u8]) -> bool {
    let mut folded = 0_u8;

    for at in 0..bytes.len() {
        // SAFETY: `at` is under the slice's length, inside it.
        folded |= unsafe { bytes.as_ptr().add(at).read_volatile() };
    }

    folded == 0
}
