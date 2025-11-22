// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::MemEncodeBufError;
use crate::mem_encode_buf::MemEncodeBuf;

#[test]
fn test_new_creates_buffer_with_correct_capacity() {
    let buf = MemEncodeBuf::new(4);
    assert_eq!(buf.len(), 4);
}

#[test]
fn test_new_zero_fills_all_elements() {
    let buf = MemEncodeBuf::new(4);
    assert!(buf.as_slice().iter().all(|w| *w == 0));
}

#[test]
fn test_new_resets_cursor_to_zero() {
    let buf = MemEncodeBuf::new(8);
    assert_eq!(buf.cursor(), 0);
}

#[test]
fn test_is_empty_returns_false_when_buffer_has_capacity() {
    let buf = MemEncodeBuf::new(4);
    assert!(!buf.is_empty());
}

#[test]
fn test_is_empty_returns_true_when_buffer_has_zero_capacity() {
    let buf = MemEncodeBuf::new(0);
    assert!(buf.is_empty());
}

#[test]
fn test_drain_byte_appends_byte_and_increments_cursor() {
    let mut buf = MemEncodeBuf::new(2);
    let mut u8 = u8::MAX;

    buf.drain_byte(&mut u8).unwrap();

    assert_eq!(buf.cursor(), 1);
    assert_eq!(buf.as_slice()[0], u8::MAX);

    // Assert zeroization!
    assert_eq!(u8, 0);
}

#[test]
fn test_drain_byte_returns_error_when_capacity_is_exceeded() {
    let mut buf = MemEncodeBuf::new(1);
    let mut u8_1 = 127u8;
    let mut u8_2 = u8::MAX;

    buf.drain_byte(&mut u8_1).unwrap();

    let result = buf.drain_byte(&mut u8_2);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeBufError::CapacityExceededError)
    ));

    // Assert zeroization!
    assert_eq!(u8_1, 0);
    assert_eq!(u8_2, 0);
    assert!(buf.as_slice().iter().all(|b| *b == 0));
}

#[test]
fn test_drain_byte_writes_bytes_in_correct_positions() {
    let mut buf = MemEncodeBuf::new(2);
    let mut u8_1 = 127u8;
    let mut u8_2 = u8::MAX;

    buf.drain_byte(&mut u8_1).unwrap();
    buf.drain_byte(&mut u8_2).unwrap();

    assert_eq!(buf.as_slice(), [127u8, u8::MAX]);

    // Assert zeroization!
    assert_eq!(u8_1, 0);
    assert_eq!(u8_2, 0);
}

#[test]
fn test_reset_with_capacity_clears_previous_contents_and_resets_cursor() {
    let mut buf = MemEncodeBuf::new(2);
    let mut u8_1 = 127u8;
    let mut u8_2 = u8::MAX;

    buf.drain_byte(&mut u8_1).unwrap();
    buf.drain_byte(&mut u8_2).unwrap();

    buf.reset_with_capacity(2);
    assert_eq!(buf.cursor(), 0);

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|w| *w == 0));
    assert_eq!(u8_1, 0);
    assert_eq!(u8_2, 0);
}

#[test]
fn test_reset_with_capacity_reallocates_with_new_capacity() {
    let mut buf = MemEncodeBuf::new(2);
    assert_eq!(buf.len(), 2);

    buf.reset_with_capacity(5);
    assert_eq!(buf.len(), 5);
}

#[test]
fn test_drain_bytes_drains_and_zeroizes_src_on_success() {
    let mut buf = MemEncodeBuf::new(2);
    let mut bytes = [1u8, 2u8];

    buf.drain_bytes(&mut bytes).unwrap();

    // Assert zeroization!
    assert!(bytes.iter().all(|b| *b == 0));
    assert_eq!(buf.as_slice(), [1u8, 2u8]);
}

#[test]
fn test_drain_bytes_zeroizes_buf_and_src_on_capacity_error() {
    let mut buf = MemEncodeBuf::new(1);
    let mut bytes = [1u8, 2u8];

    let result = buf.drain_bytes(&mut bytes);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeBufError::CapacityExceededError)
    ));

    // Assert zeroization!
    assert!(bytes.iter().all(|b| *b == 0));
    assert!(buf.as_mut_slice().iter().all(|b| *b == 0));
}

#[test]
fn test_drain_bytes_returns_error_when_cursor_addition_would_overflow() {
    let mut buf = MemEncodeBuf::new(10);
    buf.set_cursor_for_test(usize::MAX - 5);

    let mut bytes = [1u8; 10];

    let result = buf.drain_bytes(&mut bytes);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeBufError::CapacityExceededError)
    ));

    // Assert zeroization!
    assert!(bytes.iter().all(|b| *b == 0));
}

#[test]
fn test_debug_does_not_expose_buffer_content() {
    let mut buf = MemEncodeBuf::new(4);
    let mut sensitive_data = [0xDE, 0xAD, 0xBE, 0xEF];

    buf.drain_bytes(&mut sensitive_data).unwrap();

    let debug_output = format!("{:?}", buf);

    // Assert that sensitive bytes are NOT in debug output
    assert!(!debug_output.contains("DE"));
    assert!(!debug_output.contains("AD"));
    assert!(!debug_output.contains("BE"));
    assert!(!debug_output.contains("EF"));
    assert!(!debug_output.contains("222")); // 0xDE = 222
    assert!(!debug_output.contains("173")); // 0xAD = 173
    assert!(!debug_output.contains("190")); // 0xBE = 190
    assert!(!debug_output.contains("239")); // 0xEF = 239

    // Assert that REDACTED marker is present
    assert!(debug_output.contains("REDACTED"));

    // Assert that structural info is present
    assert!(debug_output.contains("len"));
    assert!(debug_output.contains("cursor"));
    assert!(debug_output.contains("4")); // len should be 4
}
