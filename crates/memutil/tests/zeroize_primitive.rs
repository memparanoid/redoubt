// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memutil::zeroize_primitive;

#[test]
fn test_zeroize_primitive_integers() {
    let mut u8_val = 255u8;
    zeroize_primitive(&mut u8_val);
    assert_eq!(u8_val, 0);

    let mut u16_val = 12345u16;
    zeroize_primitive(&mut u16_val);
    assert_eq!(u16_val, 0);

    let mut u32_val = 987654321u32;
    zeroize_primitive(&mut u32_val);
    assert_eq!(u32_val, 0);

    let mut u64_val = 123456789012345u64;
    zeroize_primitive(&mut u64_val);
    assert_eq!(u64_val, 0);

    let mut u128_val = 999999999999999999999u128;
    zeroize_primitive(&mut u128_val);
    assert_eq!(u128_val, 0);

    let mut i32_val = -42i32;
    zeroize_primitive(&mut i32_val);
    assert_eq!(i32_val, 0);

    let mut usize_val = 424242usize;
    zeroize_primitive(&mut usize_val);
    assert_eq!(usize_val, 0);
}

#[test]
fn test_zeroize_primitive_bool() {
    let mut flag = true;
    zeroize_primitive(&mut flag);
    assert_eq!(flag, false);
}

#[test]
fn test_zeroize_primitive_floats() {
    let mut f32_val = 3.14159f32;
    zeroize_primitive(&mut f32_val);
    assert_eq!(f32_val, 0.0);

    let mut f64_val = 2.718281828f64;
    zeroize_primitive(&mut f64_val);
    assert_eq!(f64_val, 0.0);
}

#[test]
fn test_zeroize_primitive_char() {
    let mut ch = 'A';
    zeroize_primitive(&mut ch);
    assert_eq!(ch, '\0');
}
