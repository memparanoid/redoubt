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
    // Note: proc-macro-crate uses underscores internally, not hyphens
    let ts_3 = find_root_with_candidates(&["memcode_derive", "memcode_core"]);
    println!("{:?}", ts_3);
    assert_eq!(format!("{:?}", ts_3), "TokenStream [Ident { sym: crate }]");

    let ts_4 = find_root_with_candidates(&["memcode_core", "memcode_derive"]);
    println!("{:?}", ts_4);
    assert_eq!(
        format!("{:?}", ts_4),
        "TokenStream [Ident { sym: memcode_core }]"
    );
}

#[test]
fn snapshot_named_struct_with_lifetime_generics_ok() {
    let derive_input = parse_quote! {
        #[derive(MemCodec)]
        struct Sigma<'alpha, Tau> where Tau: memcode_core::MemCode + memcode_core::MemDecode + Clone {
            pub alpha: Vec<u8>,
            pub beta: [u8; 32],
            pub gamma: &'alpha mut Tau,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(MemCodec)]
        struct Sigma {
            pub alpha: Vec<u8>,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_tuple_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(MemCodec)]
        struct Sigma(Vec<u8>, [u8; 16], [u8; 32]);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_empty_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(MemCodec)]
        struct Sigma;
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_enum_fails() {
    use std::panic::catch_unwind;

    let derive_input = parse_quote! {
        #[derive(MemCodec)]
        enum Lambda {
            Phi,
            Heta,
        }
    };

    let result = catch_unwind(|| {
        let _ = expand(derive_input).expect("expand failed");
    });

    assert!(result.is_err());
}
