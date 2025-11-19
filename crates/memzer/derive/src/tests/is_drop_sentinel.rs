// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use syn::{Type, parse_quote};

use crate::is_drop_sentinel_type;

#[test]
fn test_is_drop_sentinel_type_with_drop_sentinel() {
    let ty: Type = parse_quote! { DropSentinel };
    assert!(is_drop_sentinel_type(&ty));
}

#[test]
fn test_is_drop_sentinel_type_with_qualified_path() {
    let ty: Type = parse_quote! { crate::DropSentinel };
    assert!(is_drop_sentinel_type(&ty));
}

#[test]
fn test_is_drop_sentinel_type_with_reference() {
    let ty: Type = parse_quote! { &'static str };
    assert!(!is_drop_sentinel_type(&ty));
}

#[test]
fn test_is_drop_sentinel_type_with_vec() {
    let ty: Type = parse_quote! { Vec<u8> };
    assert!(!is_drop_sentinel_type(&ty));
}

#[test]
fn test_is_drop_sentinel_type_with_tuple() {
    let ty: Type = parse_quote! { (u8, u16) };
    assert!(!is_drop_sentinel_type(&ty));
}

#[test]
fn test_is_drop_sentinel_type_with_array() {
    let ty: Type = parse_quote! { [u8; 32] };
    assert!(!is_drop_sentinel_type(&ty));
}
