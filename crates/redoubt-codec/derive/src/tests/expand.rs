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
fn test_find_root_with_candidates_not_found() {
    // No candidates found -> compile_error
    let ts_1 = find_root_with_candidates(&["a", "b"]);
    insta::assert_snapshot!(pretty(ts_1));

    let ts_2 = find_root_with_candidates(&["a"]);
    insta::assert_snapshot!(pretty(ts_2));
}

#[test]
fn test_find_root_with_candidates_itself() {
    // FoundCrate::Itself (this crate)
    let ts = find_root_with_candidates(&["redoubt-codec-derive", "redoubt-codec-core"]);
    assert_eq!(format!("{:?}", ts), "TokenStream [Ident { sym: crate }]");
}

#[test]
fn test_find_root_with_candidates_name() {
    // FoundCrate::Name (external crate)
    let ts = find_root_with_candidates(&["redoubt-codec-core", "redoubt-codec-derive"]);
    assert_eq!(
        format!("{:?}", ts),
        "TokenStream [Ident { sym: redoubt_codec_core }]"
    );
}

#[test]
fn test_find_root_with_candidates_path_not_found() {
    // Path syntax with crate not found -> falls through to next candidate
    let ts = find_root_with_candidates(&["nonexistent::submod", "redoubt-codec-core"]);
    assert_eq!(
        format!("{:?}", ts),
        "TokenStream [Ident { sym: redoubt_codec_core }]"
    );
}

#[test]
fn test_find_root_with_candidates_path_name() {
    // Path syntax with FoundCrate::Name (external crate + path)
    let ts = find_root_with_candidates(&["dummy-codec::submod"]);
    assert!(format!("{:?}", ts).contains("dummy_codec"));
    assert!(format!("{:?}", ts).contains("submod"));
}

#[test]
fn test_find_root_with_candidates_path_itself() {
    // Path syntax with FoundCrate::Itself (this crate + path)
    let ts = find_root_with_candidates(&["redoubt-codec-derive::some_path"]);
    assert!(format!("{:?}", ts).contains("crate"));
    assert!(format!("{:?}", ts).contains("some_path"));
}

#[test]
fn test_find_root_with_candidates_path_name_invalid() {
    // Path syntax with FoundCrate::Name + unparseable path (triggers unwrap_or_else)
    let ts = find_root_with_candidates(&["dummy-codec::("]);
    assert!(format!("{:?}", ts).contains("dummy_codec"));
}

#[test]
fn test_find_root_with_candidates_path_itself_invalid() {
    // Path syntax with FoundCrate::Itself + unparseable path (triggers unwrap_or_else)
    let ts = find_root_with_candidates(&["redoubt-codec-derive::("]);
    assert!(format!("{:?}", ts).contains("crate"));
}

#[test]
fn snapshot_named_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
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
        #[derive(RedoubtCodec)]
        struct Data(Vec<u8>, u64, u32);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_unit_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Empty;
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_struct_with_generics_ok() {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Container<T> where T: redoubt_codec::BytesRequired + redoubt_codec::Encode + redoubt_codec::Decode {
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
        #[derive(RedoubtCodec)]
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
        #[derive(RedoubtCodec)]
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
        #[derive(RedoubtCodec)]
        struct Sigma(Vec<u8>, [u8; 32], #[codec(default)] [u8; 16]);
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_non_default_codec_attr() {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
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
        #[derive(RedoubtCodec)]
        struct Sigma {
            pub alpha: Vec<u8>,
            #[serde(default)]
            pub beta: [u8; 32],
        }
    };

    let token_stream = expand(derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}
