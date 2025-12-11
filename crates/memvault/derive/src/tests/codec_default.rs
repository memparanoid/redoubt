// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use syn::{Field, parse_quote};

use crate::has_codec_default;

// === === === === === === === === === ===
// has_codec_default() tests
// === === === === === === === === === ===

#[test]
fn test_field_with_codec_default_returns_true() {
    let field: Field = parse_quote! {
        #[codec(default)]
        pub alpha: Vec<u8>
    };
    assert!(has_codec_default(&field.attrs));
}

#[test]
fn test_field_without_attrs_returns_false() {
    let field: Field = parse_quote! {
        pub alpha: Vec<u8>
    };
    assert!(!has_codec_default(&field.attrs));
}

#[test]
fn test_field_with_other_codec_attr_returns_false() {
    let field: Field = parse_quote! {
        #[codec(skip)]
        pub alpha: Vec<u8>
    };
    assert!(!has_codec_default(&field.attrs));
}

#[test]
fn test_field_with_non_codec_attr_returns_false() {
    let field: Field = parse_quote! {
        #[serde(default)]
        pub alpha: Vec<u8>
    };
    assert!(!has_codec_default(&field.attrs));
}

#[test]
fn test_field_with_multiple_attrs_including_codec_default() {
    let field: Field = parse_quote! {
        #[serde(rename = "alpha")]
        #[codec(default)]
        #[allow(dead_code)]
        pub alpha: Vec<u8>
    };
    assert!(has_codec_default(&field.attrs));
}

#[test]
fn test_field_with_codec_default_in_complex_list() {
    let field: Field = parse_quote! {
        #[codec(default, skip_serializing)]
        pub alpha: Vec<u8>
    };
    assert!(has_codec_default(&field.attrs));
}
