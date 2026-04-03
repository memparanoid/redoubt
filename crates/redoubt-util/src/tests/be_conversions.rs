// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::*;

// =============================================================================
// u32_from_be()
// =============================================================================

#[test]
fn test_u32_from_be() {
    let mut value: u32 = 0;
    let mut bytes = [0x01, 0x02, 0x03, 0x04];

    u32_from_be(&mut value, &mut bytes);

    assert_eq!(value, 0x01020304);
    assert_eq!(bytes, [0, 0, 0, 0]);
}

#[test]
fn test_u32_from_be_max() {
    let mut value: u32 = 0;
    let mut bytes = [0xFF, 0xFF, 0xFF, 0xFF];

    u32_from_be(&mut value, &mut bytes);

    assert_eq!(value, 0xFFFFFFFF);
    assert_eq!(bytes, [0, 0, 0, 0]);
}

#[test]
fn test_u32_from_be_zeros() {
    let mut value: u32 = 0x12345678;
    let mut bytes = [0x00, 0x00, 0x00, 0x00];

    u32_from_be(&mut value, &mut bytes);

    assert_eq!(value, 0);
}

// =============================================================================
// u32_to_be()
// =============================================================================

#[test]
fn test_u32_to_be() {
    let mut value: u32 = 0x01020304;
    let mut bytes = [0u8; 4];

    u32_to_be(&mut value, &mut bytes);

    assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04]);
    assert_eq!(value, 0);
}

#[test]
fn test_u32_to_be_max() {
    let mut value: u32 = 0xFFFFFFFF;
    let mut bytes = [0u8; 4];

    u32_to_be(&mut value, &mut bytes);

    assert_eq!(bytes, [0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(value, 0);
}

#[test]
fn test_u32_to_be_roundtrip() {
    let original: u32 = 0xDEADBEEF;
    let mut value = original;
    let mut bytes = [0u8; 4];

    u32_to_be(&mut value, &mut bytes);

    let mut restored: u32 = 0;
    u32_from_be(&mut restored, &mut bytes);

    assert_eq!(restored, original);
}
