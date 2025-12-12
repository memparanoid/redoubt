// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use syn::{Type, parse_quote};

use crate::is_drop_sentinel_type;

// === === === === === === === === === ===
// is_drop_sentinel_type() tests
// === === === === === === === === === ===

#[test]
fn test_drop_sentinel_simple_path() {
    let ty: Type = parse_quote!(ZeroizeOnDropSentinel);
    assert!(is_drop_sentinel_type(&ty));
}

#[test]
fn test_drop_sentinel_qualified_path() {
    let ty: Type = parse_quote!(memzer::ZeroizeOnDropSentinel);
    assert!(is_drop_sentinel_type(&ty));
}

#[test]
fn test_drop_sentinel_fully_qualified_path() {
    let ty: Type = parse_quote!(::memzer::ZeroizeOnDropSentinel);
    assert!(is_drop_sentinel_type(&ty));
}

#[test]
fn test_non_drop_sentinel_type_returns_false() {
    let ty: Type = parse_quote!(Vec<u8>);
    assert!(!is_drop_sentinel_type(&ty));
}

#[test]
fn test_similar_name_returns_false() {
    let ty: Type = parse_quote!(ZeroizeOnDropSentinelLike);
    assert!(!is_drop_sentinel_type(&ty));
}

#[test]
fn test_primitive_type_returns_false() {
    let ty: Type = parse_quote!(u64);
    assert!(!is_drop_sentinel_type(&ty));
}

#[test]
fn test_array_type_returns_false() {
    let ty: Type = parse_quote!([u8; 32]);
    assert!(!is_drop_sentinel_type(&ty));
}

#[test]
fn test_reference_type_returns_false() {
    let ty: Type = parse_quote!(&'a mut Vec<u8>);
    assert!(!is_drop_sentinel_type(&ty));
}
