// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Hex in Rust, by masks rather than branches on a digit, with no promise
//! about the registers it goes through or the time it takes.

/// `src` as lowercase hex digits in `dst`, two per byte.
///
/// # Safety
///
/// `dst` twice as long as `src`.
pub(crate) unsafe fn bytes_to_hex(src: &[u8], dst: &mut [u8]) {
    for (byte, digits) in src.iter().zip(dst.as_chunks_mut::<2>().0.iter_mut()) {
        digits[0] = nibble_to_digit(byte >> 4);
        digits[1] = nibble_to_digit(byte & 0x0F);
    }
}

/// The bytes the digits in `src` spell, in `dst`, and whether every one of
/// them was a hex digit; `dst` all zeros when not.
///
/// # Safety
///
/// `src` of even length, and `dst` half as long.
pub(crate) unsafe fn hex_to_bytes(src: &[u8], dst: &mut [u8]) -> bool {
    let mut refused = 0_u8;

    for digit in src {
        refused |= !is_digit(*digit) & 1;
    }

    if refused != 0 {
        dst.fill(0);

        return false;
    }

    for (pair, byte) in src.as_chunks::<2>().0.iter().zip(dst.iter_mut()) {
        *byte = (digit_to_nibble(pair[0]) << 4) | digit_to_nibble(pair[1]);
    }

    true
}

fn nibble_to_digit(nibble: u8) -> u8 {
    let past_nine = 0_u8.wrapping_sub(u8::from(nibble > 9));

    nibble + 0x30 + (past_nine & 0x27)
}

fn is_digit(c: u8) -> u8 {
    let number = u8::from((c ^ 0x30) < 10);
    let letter = u8::from((c & !0x20).wrapping_sub(65) < 6);

    number | letter
}

fn digit_to_nibble(c: u8) -> u8 {
    let number = c ^ 0x30;
    let is_number = 0_u8.wrapping_sub(u8::from(number < 10));
    let letter = (c & !0x20).wrapping_sub(55);

    (number & is_number) | (letter & !is_number)
}
