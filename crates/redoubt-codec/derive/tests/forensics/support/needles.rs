// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// Sixteen distinct bytes, so one fills a `u128` and a run that extends did not
/// extend by luck; ASCII, because decoding a string refuses what is not UTF-8.
pub(crate) const NEEDLE: &[u8; 16] = b"q7Xv2Lp9Rz4Nb8Kt";

/// The needle, built from its last byte to its first and never turned around:
/// the forward bytes must not exist in this process.
pub(crate) fn backwards() -> Vec<u8> {
    NEEDLE.iter().rev().copied().collect()
}
