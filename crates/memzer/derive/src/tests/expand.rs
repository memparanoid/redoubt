// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use prettyplease;
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

#[test]
fn test_find_root_with_candidates() {
    let ts_1 = find_root_with_candidates(&["a", "b"]);
    insta::assert_snapshot!(pretty(ts_1));
    let ts_2 = find_root_with_candidates(&["a"]);
    insta::assert_snapshot!(pretty(ts_2));

    // Just to cover all branches
    let ts_3 = find_root_with_candidates(&["memzer_derive", "memzer_core"]);
    println!("{:?}", ts_3);
    assert_eq!(format!("{:?}", ts_3), "TokenStream [Ident { sym: crate }]");

    let ts_4 = find_root_with_candidates(&["memzer_core", "memzer_derive"]);
    println!("{:?}", ts_4);
    assert_eq!(
        format!("{:?}", ts_4),
        "TokenStream [Ident { sym: memzer_core }]"
    );
}

#[test]
fn snapshot_named_struct_with_lifetime_generics_ok() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Sigma<'alpha, Tau> where Tau: Clone {
            pub alpha: u8,
            pub beta: (u32, u64),
            pub gamma: &'alpha mut Tau,
            __drop_sentinel: DropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Sigma {
            pub alpha: u8,
            __drop_sentinel: DropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_empty_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Sigma {
            __drop_sentinel: DropSentinel,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_tuple_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Sigma(u8, u16, u32, DropSentinel);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_without_sentinel_fails() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Sigma {
            pub alpha: u8,
        }
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}

#[test]
fn snapshot_tuple_struct_without_sentinel_fails() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Sigma(u8, u16, u32);
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}

#[test]
fn snapshot_unit_struct_fails() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Sigma;
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}

#[test]
fn snapshot_tuple_struct_with_non_drop_sentinel_types() {
    // Test que el tipo detection funciona con tipos complejos
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Sigma(
            &'static str,
            Vec<u8>,
            DropSentinel,
        );
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_enum_fails() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        enum Sigma {
            Alpha,
            Beta,
        }
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}
