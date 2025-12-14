// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use syn::parse_quote;

use crate::{expand, find_root_with_candidates};

fn pretty(ts: proc_macro2::TokenStream) -> String {
    let file = syn::parse2(ts).unwrap_or_else(|_| {
        syn::parse_quote! {
            mod __dummy { }
        }
    });
    prettyplease::unparse(&file)
}

// === === === === === === === === === ===
// Helper function tests
// === === === === === === === === === ===

#[test]
fn test_find_root_with_candidates() {
    let ts_1 = find_root_with_candidates(&["a", "b"]);
    insta::assert_snapshot!(pretty(ts_1));
    let ts_2 = find_root_with_candidates(&["a"]);
    insta::assert_snapshot!(pretty(ts_2));

    // Just to cover all branches
    let ts_3 = find_root_with_candidates(&["redoubt-zero-derive", "redoubt-zero-core"]);
    println!("{:?}", ts_3);
    assert_eq!(format!("{:?}", ts_3), "TokenStream [Ident { sym: crate }]");

    let ts_4 = find_root_with_candidates(&["redoubt-zero-core", "redoubt-zero-derive"]);
    println!("{:?}", ts_4);
    assert_eq!(
        format!("{:?}", ts_4),
        "TokenStream [Ident { sym: redoubt_zero_core }]"
    );
}

// === === === === === === === === === ===
// Named structs - Basic
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Delta {
            pub alpha: u8,
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_empty_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Epsilon {
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_lifetime_generics_ok() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Sigma<'alpha, Tau> where Tau: Clone {
            pub alpha: u8,
            pub beta: u16,
            pub gamma: &'alpha mut Tau,
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Named structs - #[fast_zeroize(skip)]
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_with_memzer_skip_on_one_field() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Mu {
            pub alpha: Vec<u8>,
            #[fast_zeroize(skip)]
            pub beta: [u8; 32],
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_memzer_skip_on_immut_ref() {
    // Test that #[fast_zeroize(skip)] works with immutable references
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Xi<'a> {
            pub alpha: Vec<u8>,
            #[fast_zeroize(skip)]
            pub beta: &'a str,
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Named structs - #[fast_zeroize(drop)]
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_with_memzer_drop() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        #[fast_zeroize(drop)]
        struct Rho {
            pub alpha: Vec<u8>,
            pub beta: [u8; 32],
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_generics_and_memzer_drop() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        #[fast_zeroize(drop)]
        struct Tau<'a, T> where T: Clone {
            pub alpha: u8,
            pub beta: &'a mut T,
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Named structs - Comprehensive
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_with_multiple_memzer_attrs() {
    // Comprehensive test with multiple attribute types:
    // - #[fast_zeroize(drop)] on struct
    // - Meta::Path (#[repr(C)]) and Meta::NameValue (#[doc = "..."]) at struct level
    // - #[fast_zeroize(skip)] on a field
    // - #[fast_zeroize(other)] on a field (False branch of contains("skip"))
    // - Meta::Path (#[allow(dead_code)]) on a field
    // - Meta::NameValue (#[doc = "..."]) on a field
    // - Meta::List non-RedoubtZero (#[arbitrary(config)]) on a field
    // - Normal field without attributes
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        #[repr(C)]
        #[doc = "Comprehensive test struct"]
        #[fast_zeroize(drop)]
        struct Chi<'a> {
            pub alpha: Vec<u8>,
            #[fast_zeroize(skip)]
            pub beta: &'a str,
            #[fast_zeroize(custom_attr)]
            pub gamma: [u8; 32],
            #[allow(dead_code)]
            pub delta: u64,
            #[arbitrary(config)]
            #[doc = "Field documentation"]
            pub epsilon: u32,
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Tuple structs - Basic
// === === === === === === === === === ===

#[test]
fn snapshot_tuple_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Zeta(u8, u16, u32, ZeroizeOnDropSentinel);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_tuple_struct_with_non_drop_sentinel_types() {
    // Test que el tipo detection funciona con tipos complejos
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Kappa(
            Vec<u16>,
            Vec<u8>,
            ZeroizeOnDropSentinel,
        );
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_tuple_struct_with_mut_ref() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Upsilon<'a>(u8, &'a mut Vec<u8>, ZeroizeOnDropSentinel);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Tuple structs - #[fast_zeroize(skip)]
// === === === === === === === === === ===

#[test]
fn snapshot_tuple_struct_with_memzer_skip() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Nu(
            Vec<u8>,
            #[fast_zeroize(skip)]
            [u8; 32],
            ZeroizeOnDropSentinel,
        );
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Tuple structs - #[fast_zeroize(drop)]
// === === === === === === === === === ===

#[test]
fn snapshot_tuple_struct_with_memzer_drop() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        #[fast_zeroize(drop)]
        struct Sigma(Vec<u8>, [u8; 32], ZeroizeOnDropSentinel);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Tuple structs - Comprehensive
// === === === === === === === === === ===

#[test]
fn snapshot_tuple_struct_with_multiple_memzer_attrs() {
    // Comprehensive test with multiple attribute types:
    // - #[fast_zeroize(drop)] on struct
    // - Meta::Path (#[repr(C)]) and Meta::NameValue (#[doc = "..."]) at struct level
    // - #[fast_zeroize(skip)] on a field
    // - #[fast_zeroize(other)] on a field (False branch of contains("skip"))
    // - Meta::Path (#[allow(dead_code)]) on a field
    // - Meta::NameValue (#[doc = "..."]) on a field
    // - Normal field without attributes
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        #[repr(C)]
        #[doc = "Comprehensive tuple test struct"]
        #[fast_zeroize(drop)]
        struct Psi<'a>(
            Vec<u8>,
            #[fast_zeroize(skip)]
            &'a str,
            #[fast_zeroize(custom_attr)]
            [u8; 32],
            #[allow(dead_code)]
            #[doc = "Tuple field doc"]
            u64,
            ZeroizeOnDropSentinel,
        );
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Error cases
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_without_sentinel_fails() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Eta {
            pub alpha: u8,
        }
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}

#[test]
fn snapshot_tuple_struct_without_sentinel_fails() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Theta(u8, u16, u32);
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}

#[test]
fn snapshot_unit_struct_fails() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Iota;
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}

#[test]
fn snapshot_enum_fails() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        enum Lambda {
            Alpha,
            Beta,
        }
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}

#[test]
fn snapshot_immut_ref_without_skip_fails() {
    // Test that immutable reference without #[fast_zeroize(skip)] produces a helpful error
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Pi<'a> {
            pub alpha: Vec<u8>,
            pub beta: &'a str,
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let result = expand(derive_input);
    assert!(result.is_err());

    // Verify the error message is helpful
    let err_str = format!("{}", result.unwrap_err());
    assert!(err_str.contains("immutable reference"));
    assert!(err_str.contains("#[fast_zeroize(skip)]"));
}

#[test]
fn snapshot_tuple_immut_ref_without_skip_fails() {
    // Test that immutable reference in tuple struct without #[fast_zeroize(skip)] produces a helpful error
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Phi<'a>(Vec<u8>, &'a str, ZeroizeOnDropSentinel);
    };

    let result = expand(derive_input);
    assert!(result.is_err());

    // Verify the error message is helpful and shows field index
    let err_str = format!("{}", result.unwrap_err());
    assert!(err_str.contains("immutable reference"));
    assert!(err_str.contains("#[fast_zeroize(skip)]"));
    assert!(err_str.contains("index"));
}
