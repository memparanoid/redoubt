// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use syn::parse_quote;

use crate::{is_immut_reference_type, is_mut_reference_type};

#[test]
fn test_is_mut_reference_type_with_mut_ref() {
    let ty: syn::Type = parse_quote! { &'a mut Vec<u8> };
    assert!(is_mut_reference_type(&ty));
}

#[test]
fn test_is_mut_reference_type_with_immut_ref() {
    let ty: syn::Type = parse_quote! { &'a str };
    assert!(!is_mut_reference_type(&ty));
}

#[test]
fn test_is_mut_reference_type_with_owned() {
    let ty: syn::Type = parse_quote! { Vec<u8> };
    assert!(!is_mut_reference_type(&ty));
}

#[test]
fn test_is_immut_reference_type_with_immut_ref() {
    let ty: syn::Type = parse_quote! { &'a str };
    assert!(is_immut_reference_type(&ty));
}

#[test]
fn test_is_immut_reference_type_with_mut_ref() {
    let ty: syn::Type = parse_quote! { &'a mut Vec<u8> };
    assert!(!is_immut_reference_type(&ty));
}

#[test]
fn test_is_immut_reference_type_with_owned() {
    let ty: syn::Type = parse_quote! { Vec<u8> };
    assert!(!is_immut_reference_type(&ty));
}
