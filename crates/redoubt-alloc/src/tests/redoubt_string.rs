// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::RedoubtString;
use alloc::string::String;
use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

/// Every byte of the allocation, past the length included.
fn capacity_is_zeroized(s: &RedoubtString) -> bool {
    // SAFETY: under `dirty = 0xFF` the allocator writes every byte of a block
    // it hands out, so the bytes past the length are initialized, and the
    // range is the string's own allocation.
    let whole = unsafe { core::slice::from_raw_parts(s.as_str().as_ptr(), s.capacity()) };

    whole.iter().all(|byte| *byte == 0)
}

// ╔════════════════════════════════════════════════════════════════════════════╗
// ║ ZEROIZATION                                                                ║
// ╚════════════════════════════════════════════════════════════════════════════╝

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_redoubt_string_is_zeroizable() {
    let mut s = RedoubtString::from_str("sensitive");

    assert!(!s.is_zeroized());

    s.fast_zeroize();
    assert!(s.is_zeroized());
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_redoubt_string_zeroizes_on_drop() {
    let s = RedoubtString::from_str("sensitive");

    assert!(!s.is_zeroized());

    s.assert_zeroize_on_drop();
}

// =============================================================================
// new()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_new() {
    let s = RedoubtString::new();

    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
}

// =============================================================================
// with_capacity()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_with_capacity() {
    let s = RedoubtString::with_capacity(10);

    assert_eq!(s.len(), 0);
    assert!(s.capacity() >= 10);
}

/// The allocator hands out a freed block, or a piece of one, as its last owner
/// left it.
#[redoubt_forensics::test(dirty = 0xFF)]
fn test_with_capacity_is_zeroized_over_its_whole_capacity() {
    let s = RedoubtString::with_capacity(1024);

    // Assert zeroization!
    assert!(capacity_is_zeroized(&s));
}

// =============================================================================
// from_mut_string() / from_str()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_from_mut_string() {
    let mut data = String::from("hello");
    let s = RedoubtString::from_mut_string(&mut data);

    assert_eq!(s.as_str(), "hello");
    assert!(data.is_zeroized());
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_from_str() {
    let s = RedoubtString::from_str("world");
    assert_eq!(s.as_str(), "world");
}

// =============================================================================
// len(), is_empty(), capacity()
// =============================================================================

// Tested implicitly in other tests

// =============================================================================
// extend_from_mut_string()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_mut_string() {
    let mut dest = RedoubtString::new();
    let mut src = String::from("secret password");

    let original_len = src.len();
    dest.extend_from_mut_string(&mut src);

    // Data moved to dest
    assert_eq!(dest.as_str(), "secret password");
    assert_eq!(dest.len(), original_len);

    // Source zeroized and cleared
    assert!(src.is_zeroized());
    assert_eq!(src.len(), 0);
    assert!(src.is_empty());
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_mut_string_appends() {
    let mut dest = RedoubtString::new();
    dest.extend_from_str("prefix: ");

    let mut src = String::from("data");
    dest.extend_from_mut_string(&mut src);

    assert_eq!(dest.as_str(), "prefix: data");
    assert!(src.is_zeroized());
    assert_eq!(src.len(), 0);
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_mut_string_zeroizes_source() {
    let mut dest = RedoubtString::new();
    let mut src = String::from("sensitive_data_12345");

    dest.extend_from_mut_string(&mut src);

    // Source should be zeroized, empty and cleared
    assert!(src.is_zeroized());
    assert_eq!(src.len(), 0);
    assert!(src.is_empty());
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_mut_string_with_sufficient_capacity() {
    use redoubt_zero::ZeroizationProbe;

    // Create with large capacity
    let mut dest = RedoubtString::with_capacity(1000);
    let initial_capacity = dest.capacity();

    // Drain multiple small strings without exceeding capacity
    for _ in 0..10 {
        let mut src = alloc::string::String::from("data");
        dest.extend_from_mut_string(&mut src);

        // Verify source was zeroized
        assert!(src.is_zeroized());
        assert_eq!(src.len(), 0);

        // Verify capacity did NOT grow
        assert_eq!(dest.capacity(), initial_capacity);
    }

    // Final length should be 10 * 4 = 40 bytes
    assert_eq!(dest.len(), 40);
    assert_eq!(dest.capacity(), initial_capacity);
}

// =============================================================================
// replace_from_mut_string()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_replace_from_mut_string() {
    let mut dest = RedoubtString::new();
    dest.extend_from_str("old content");

    let mut src = String::from("new content");
    dest.replace_from_mut_string(&mut src);

    // Destination replaced (not appended)
    assert_eq!(dest.as_str(), "new content");

    // Source zeroized
    assert!(src.is_zeroized());
    assert!(src.is_empty());
}

// =============================================================================
// extend_from_str()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str() {
    let mut s = RedoubtString::new();
    s.extend_from_str("hello");

    assert_eq!(s.len(), 5);
    assert_eq!(s.as_str(), "hello");
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str_appends() {
    let mut s = RedoubtString::new();
    s.extend_from_str("hello ");
    s.extend_from_str("world");

    assert_eq!(s.as_str(), "hello world");
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str_grows_to_power_of_2() {
    let mut s = RedoubtString::new();

    // First extend: 0 → next_power_of_two(5) = 8
    s.extend_from_str("hello");
    assert!(s.capacity() >= 8);

    // Add more to trigger growth
    s.extend_from_str(" world! This is a longer string");

    // Should have grown
    assert!(s.capacity() >= s.len());
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str_chars() {
    let mut s = RedoubtString::new();
    s.extend_from_str("a");
    s.extend_from_str("b");
    s.extend_from_str("c");

    assert_eq!(s.as_str(), "abc");
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str_emoji() {
    let mut s = RedoubtString::new();
    s.extend_from_str("🦀");
    s.extend_from_str("🔒");
    s.extend_from_str("✅");

    assert_eq!(s.as_str(), "🦀🔒✅");
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str_redoubt_emoji() {
    let mut s = RedoubtString::new();
    s.extend_from_str("🇷🇪🇩🇴🇺🇧🇹");

    assert_eq!(s.as_str(), "🇷🇪🇩🇴🇺🇧🇹");
    assert_eq!(s.len(), 28);
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str_utf8_handling() {
    let mut s = RedoubtString::new();
    s.extend_from_str("Hello 世界 🦀");

    assert_eq!(s.as_str(), "Hello 世界 🦀");
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str_single_allocation() {
    let mut s = RedoubtString::new();

    // Extend a large string should do only ONE grow
    let large = "a".repeat(100);
    s.extend_from_str(&large);

    // Should grow to next_power_of_two(100) = 128
    assert_eq!(s.len(), 100);
    assert!(s.capacity() >= 128);
}

/// The capacity a growth reserves comes from the allocator holding whatever
/// its last owner left, and only the part up to the length is written over.
#[redoubt_forensics::test(dirty = 0xFF)]
fn test_extend_from_str_grows_into_zeroized_capacity() {
    let mut s = RedoubtString::new();

    for _ in 0..1024 {
        s.extend_from_str("\0");

        // Assert zeroization!
        assert!(capacity_is_zeroized(&s));
    }
}

// =============================================================================
// clear()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_clear() {
    let mut s = RedoubtString::new();
    s.extend_from_str("data");

    s.clear();

    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
}

// =============================================================================
// as_str()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_as_str() {
    let mut s = RedoubtString::new();
    s.extend_from_str("hello world");

    assert_eq!(s.as_str(), "hello world");
}

// =============================================================================
// as_mut_str()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_as_mut_str() {
    let mut s = RedoubtString::new();
    s.extend_from_str("hello");

    let str_mut = s.as_mut_str();
    str_mut.make_ascii_uppercase();

    assert_eq!(s.as_str(), "HELLO");
}

// =============================================================================
// as_string()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_as_string() {
    let mut s = RedoubtString::new();

    s.extend_from_str("hello world");

    let string_ref = s.as_string();

    assert_eq!(string_ref.as_str(), "hello world");
    assert_eq!(string_ref.len(), 11);
}

// =============================================================================
// as_mut_string()
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_as_mut_string() {
    let mut s = RedoubtString::new();

    s.extend_from_str("secret data");

    let string_mut_ref = s.as_mut_string();
    string_mut_ref.push_str(" modified");

    assert_eq!(s.as_str(), "secret data modified");
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_as_mut_string_drain() {
    let mut s1 = RedoubtString::new();
    s1.extend_from_str("destination");

    let mut s2 = RedoubtString::new();
    s2.extend_from_str("source");

    // Drain from s2 into s1 using as_mut_string
    let src_inner = s2.as_mut_string();
    s1.extend_from_mut_string(src_inner);

    assert_eq!(s1.as_str(), "destinationsource");
    assert_eq!(s2.len(), 0);
}

// =============================================================================
// Default
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_default() {
    let s = RedoubtString::default();

    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
    assert_eq!(s.capacity(), 0);
}

// =============================================================================
// Deref / DerefMut
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_deref() {
    let mut s = RedoubtString::new();

    s.extend_from_str("test");

    // Deref to &str
    let str_ref: &str = &s;
    assert_eq!(str_ref, "test");

    // DerefMut to &mut str
    let str_mut: &mut str = &mut s;
    str_mut.make_ascii_uppercase();

    assert_eq!(s.as_str(), "TEST");
}

// =============================================================================
// PartialEq / Eq
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_partial_eq_equal_strings() {
    let mut s1 = RedoubtString::new();
    s1.extend_from_str("hello world");

    let mut s2 = RedoubtString::new();
    s2.extend_from_str("hello world");

    assert_eq!(s1.as_str(), s2.as_str());
    assert!(s1 == s2);
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_partial_eq_different_strings() {
    let mut s1 = RedoubtString::new();
    s1.extend_from_str("hello world");

    let mut s2 = RedoubtString::new();
    s2.extend_from_str("hello rust");

    assert_ne!(s1.as_str(), s2.as_str());
    assert!(s1 != s2);
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_partial_eq_different_lengths() {
    let mut s1 = RedoubtString::new();
    s1.extend_from_str("hello");

    let mut s2 = RedoubtString::new();
    s2.extend_from_str("hello world");

    assert_ne!(s1.as_str(), s2.as_str());
    assert!(s1 != s2);
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_partial_eq_empty_strings() {
    let s1 = RedoubtString::new();
    let s2 = RedoubtString::new();

    assert_eq!(s1.as_str(), s2.as_str());
    assert!(s1 == s2);
}

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_partial_eq_with_unicode() {
    let mut s1 = RedoubtString::new();
    s1.extend_from_str("Hello 世界 🦀");

    let mut s2 = RedoubtString::new();
    s2.extend_from_str("Hello 世界 🦀");

    assert_eq!(s1.as_str(), s2.as_str());
    assert!(s1 == s2);
}

// =============================================================================
// Debug
// =============================================================================

#[redoubt_forensics::test(dirty = 0xFF)]
fn test_debug_redacted() {
    let mut s = RedoubtString::new();

    s.extend_from_str("secret password 123");

    let debug_output = format!("{:?}", s);

    assert!(debug_output.contains("RedoubtString"));
    assert!(debug_output.contains("REDACTED"));
    assert!(debug_output.contains("len"));
    assert!(debug_output.contains("capacity"));
    assert!(!debug_output.contains("secret"));
    assert!(!debug_output.contains("password"));
    assert!(!debug_output.contains("123"));
}
