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

#[test]
fn test_find_root_with_candidates() {
    let ts_1 = find_root_with_candidates(&["a", "b"]);
    insta::assert_snapshot!(pretty(ts_1));
    let ts_2 = find_root_with_candidates(&["a"]);
    insta::assert_snapshot!(pretty(ts_2));

    // Just to cover all branches
    // Note: proc-macro-crate uses underscores internally, not hyphens
    let ts_3 = find_root_with_candidates(&["memcodec_derive", "memcodec_core"]);
    println!("{:?}", ts_3);
    assert_eq!(format!("{:?}", ts_3), "TokenStream [Ident { sym: crate }]");

    let ts_4 = find_root_with_candidates(&["memcodec_core", "memcodec_derive"]);
    println!("{:?}", ts_4);
    assert_eq!(
        format!("{:?}", ts_4),
        "TokenStream [Ident { sym: memcodec_core }]"
    );
}

#[test]
fn snapshot_named_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Data {
            pub alpha: Vec<u8>,
            pub beta: u64,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_tuple_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Data(Vec<u8>, u64, u32);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_unit_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Empty;
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_struct_with_generics_ok() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Container<T> where T: memcodec::BytesRequired + memcodec::Encode + memcodec::Decode {
            pub value: T,
            pub count: u64,
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_enum_fails() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        enum Choice {
            A,
            B,
        }
    };

    let result = expand(derive_input);
    assert!(result.is_err());
}

// #[codec(default)]

#[test]
fn snapshot_named_struct_ok_with_codec_default() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Sigma {
            pub alpha: Vec<u8>,
            pub beta: [u8; 32],
            #[codec(default)]
            pub gamma: [u8; 16],
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_tuple_struct_ok_with_codec_default() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Sigma(Vec<u8>, [u8; 32], #[codec(default)] [u8; 16]);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_non_default_codec_attr() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Sigma {
            pub alpha: Vec<u8>,
            #[codec(skip)]
            pub beta: [u8; 32],
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_other_list_attr() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Sigma {
            pub alpha: Vec<u8>,
            #[serde(default)]
            pub beta: [u8; 32],
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}
