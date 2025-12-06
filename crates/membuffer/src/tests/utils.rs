// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::utils::fill_with_pattern;

// fill_with_pattern

#[test]
fn test_fill_with_pattern_zeros() {
    let mut buf = [0xFFu8; 16];
    fill_with_pattern(&mut buf, 0x00);
    assert!(buf.iter().all(|&b| b == 0x00));
}

#[test]
fn test_fill_with_pattern_ones() {
    let mut buf = [0x00u8; 16];
    fill_with_pattern(&mut buf, 0xFF);
    assert!(buf.iter().all(|&b| b == 0xFF));
}

#[test]
fn test_fill_with_pattern_arbitrary() {
    let mut buf = [0x00u8; 32];
    fill_with_pattern(&mut buf, 0xAB);
    assert!(buf.iter().all(|&b| b == 0xAB));
}

#[test]
fn test_fill_with_pattern_empty_slice() {
    let mut buf: [u8; 0] = [];
    fill_with_pattern(&mut buf, 0xFF);
    assert!(buf.is_empty());
}

#[test]
fn test_fill_with_pattern_single_byte() {
    let mut buf = [0x00u8; 1];
    fill_with_pattern(&mut buf, 0x42);
    assert_eq!(buf[0], 0x42);
}
