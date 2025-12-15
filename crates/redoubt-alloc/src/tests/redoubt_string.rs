// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::RedoubtString;
use alloc::string::String;

#[test]
fn test_new() {
    let s = RedoubtString::new();
    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
}

#[test]
fn test_with_capacity() {
    let s = RedoubtString::with_capacity(10);
    assert_eq!(s.len(), 0);
    assert!(s.capacity() >= 10);
}

#[test]
fn test_default() {
    let s = RedoubtString::default();
    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
    assert_eq!(s.capacity(), 0);
}

#[test]
fn test_push_str() {
    let mut s = RedoubtString::new();
    s.push_str("hello");

    assert_eq!(s.len(), 5);
    assert_eq!(s.as_str(), "hello");
}

#[test]
fn test_push_char() {
    let mut s = RedoubtString::new();
    s.push('a');
    s.push('b');
    s.push('c');

    assert_eq!(s.as_str(), "abc");
}

#[test]
fn test_push_str_grows_to_power_of_2() {
    let mut s = RedoubtString::new();

    // First push: 0 → next_power_of_two(5) = 8
    s.push_str("hello");
    assert!(s.capacity() >= 8);

    // Add more to trigger growth
    s.push_str(" world! This is a longer string");

    // Should have grown
    assert!(s.capacity() >= s.len());
}

#[test]
fn test_drain_from_string() {
    let mut dest = RedoubtString::new();
    let mut src = String::from("secret password");

    let original_len = src.len();
    dest.drain_from_string(&mut src);

    // Data moved to dest
    assert_eq!(dest.as_str(), "secret password");
    assert_eq!(dest.len(), original_len);

    // Source zeroized and cleared
    assert_eq!(src.len(), 0);
    assert!(src.is_empty());
}

#[test]
fn test_copy_from_str() {
    let mut s = RedoubtString::new();
    let data = "hello world";

    s.copy_from_str(data);

    assert_eq!(s.as_str(), "hello world");

    // Source unchanged (it's &str, can't be zeroized)
    assert_eq!(data, "hello world");
}

#[test]
fn test_drain_from_string_appends() {
    let mut dest = RedoubtString::new();
    dest.push_str("prefix: ");

    let mut src = String::from("data");
    dest.drain_from_string(&mut src);

    assert_eq!(dest.as_str(), "prefix: data");
    assert_eq!(src.len(), 0);
}

#[test]
fn test_copy_from_str_appends() {
    let mut s = RedoubtString::new();
    s.push_str("hello ");
    s.copy_from_str("world");

    assert_eq!(s.as_str(), "hello world");
}

#[test]
fn test_clear() {
    let mut s = RedoubtString::new();
    s.push_str("data");

    s.clear();

    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
}

#[test]
fn test_as_str() {
    let mut s = RedoubtString::new();
    s.push_str("hello world");

    assert_eq!(s.as_str(), "hello world");
}

#[test]
fn test_as_mut_str() {
    let mut s = RedoubtString::new();
    s.push_str("hello");

    let str_mut = s.as_mut_str();
    str_mut.make_ascii_uppercase();

    assert_eq!(s.as_str(), "HELLO");
}

#[test]
fn test_from_string() {
    let mut original = String::from("secret");
    let redoubt = RedoubtString::from(original.clone());

    assert_eq!(redoubt.as_str(), "secret");

    // Note: from() clones, so original is unchanged
    // Use drain_from_string for zeroization
}

#[test]
fn test_from_str() {
    let redoubt = RedoubtString::from("hello");
    assert_eq!(redoubt.as_str(), "hello");
}

#[test]
fn test_deref() {
    let mut s = RedoubtString::new();
    s.push_str("test");

    // Deref to &str
    let str_ref: &str = &s;
    assert_eq!(str_ref, "test");

    // DerefMut to &mut str
    let str_mut: &mut str = &mut s;
    str_mut.make_ascii_uppercase();
    assert_eq!(s.as_str(), "TEST");
}

#[test]
fn test_utf8_handling() {
    let mut s = RedoubtString::new();
    s.push_str("Hello 世界 🦀");

    assert_eq!(s.as_str(), "Hello 世界 🦀");
}

#[test]
fn test_maybe_grow_to_single_allocation() {
    let mut s = RedoubtString::new();

    // Push a large string should do only ONE grow
    let large = "a".repeat(100);
    s.push_str(&large);

    // Should grow to next_power_of_two(100) = 128
    assert_eq!(s.len(), 100);
    assert!(s.capacity() >= 128);
}

#[test]
fn test_drain_from_string_zeroizes_source() {
    let mut dest = RedoubtString::new();
    let mut src = String::from("sensitive_data_12345");

    // Get pointer before drain (for documentation purposes)
    let _ptr = src.as_ptr();

    dest.drain_from_string(&mut src);

    // Source should be empty and zeroized
    assert_eq!(src.len(), 0);
    assert!(src.is_empty());

    // Note: The actual bytes in the old allocation have been zeroized
    // but we can't safely verify this after the clear()
}

#[test]
fn test_push_emoji() {
    let mut s = RedoubtString::new();
    s.push('🦀');
    s.push('🔒');
    s.push('✅');

    assert_eq!(s.as_str(), "🦀🔒✅");
}

#[test]
fn test_push_redoubt_emoji() {
    let mut s = RedoubtString::new();
    s.push('🇷'); // R
    s.push('🇪'); // E
    s.push('🇩'); // D
    s.push('🇴'); // O
    s.push('🇺'); // U
    s.push('🇧'); // B
    s.push('🇹'); // T

    assert_eq!(s.as_str(), "🇷🇪🇩🇴🇺🇧🇹");
    assert_eq!(s.len(), 28);
}
