// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// The secret: thirty-two bytes, none repeated, so a run that extends did not
/// extend by luck.
pub(crate) const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A secret a `String` can hold: decoding one refuses what is not UTF-8.
pub(crate) const TEXT: &[u8; 32] = b"q7Xv2Lp9Rz4Nb8Kt1Mw6Hc3Yf5Gd0SjA";

/// The needle, built from its last byte to its first and never turned around:
/// the forward bytes must not exist in this process.
pub(crate) fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

pub(crate) fn half_backwards() -> Vec<u8> {
    SECRET[..16].iter().rev().copied().collect()
}

pub(crate) fn text_backwards() -> Vec<u8> {
    TEXT.iter().rev().copied().collect()
}
