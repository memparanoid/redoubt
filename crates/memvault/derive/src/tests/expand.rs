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
    // Note: proc-macro-crate uses underscores internally, not hyphens
    let ts_3 = find_root_with_candidates(&["memvault_derive", "memvault_core"]);
    println!("{:?}", ts_3);
    assert_eq!(format!("{:?}", ts_3), "TokenStream [Ident { sym: crate }]");

    let ts_4 = find_root_with_candidates(&["memvault_core", "memvault_derive"]);
    println!("{:?}", ts_4);
    assert_eq!(
        format!("{:?}", ts_4),
        "TokenStream [Ident { sym: memvault_core }]"
    );
}

// === === === === === === === === === ===
// Named structs - Basic
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(MemZer, Codec)]
        struct Data {
            pub alpha: Vec<u8>,
            pub beta: u64,
        }
    };

    let token_stream = expand(syn::parse_quote!(DataBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_single_field() {
    let derive_input = parse_quote! {
        struct Gamma {
            pub value: [u8; 32],
        }
    };

    let token_stream = expand(syn::parse_quote!(GammaBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_generics() {
    let derive_input = parse_quote! {
        struct Container<T> where T: memcodec::BytesRequired + memcodec::Encode + memcodec::Decode {
            pub value: T,
            pub count: u64,
        }
    };

    let token_stream = expand(syn::parse_quote!(ContainerBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Named structs - Field filtering
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_with_codec_default_field() {
    let derive_input = parse_quote! {
        #[derive(MemZer, Codec)]
        struct Delta {
            pub alpha: Vec<u8>,
            pub beta: [u8; 32],
            #[codec(default)]
            pub gamma: [u8; 16],
        }
    };

    let token_stream = expand(syn::parse_quote!(DeltaBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_drop_sentinel() {
    let derive_input = parse_quote! {
        #[derive(MemZer, Codec)]
        #[memzer(drop)]
        struct Epsilon {
            pub master_seed: [u8; 32],
            pub encryption_key: [u8; 32],
            #[codec(default)]
            __drop_sentinel: DropSentinel,
        }
    };

    let token_stream = expand(syn::parse_quote!(EpsilonBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_multiple_filtered_fields() {
    let derive_input = parse_quote! {
        #[derive(MemZer, Codec)]
        struct Zeta {
            pub field1: Vec<u8>,
            #[codec(default)]
            pub field2: [u8; 32],
            pub field3: u64,
            __drop_sentinel: DropSentinel,
            #[codec(default)]
            pub field4: u32,
        }
    };

    let token_stream = expand(syn::parse_quote!(ZetaBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Named structs - Edge cases
// === === === === === === === === === ===

#[test]
fn snapshot_empty_struct_with_only_sentinel() {
    let derive_input = parse_quote! {
        #[derive(MemZer)]
        struct Empty {
            #[codec(default)]
            __drop_sentinel: DropSentinel,
        }
    };

    let token_stream = expand(syn::parse_quote!(EmptyBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_struct_with_all_fields_filtered() {
    let derive_input = parse_quote! {
        struct OnlyDefaults {
            #[codec(default)]
            pub field1: u64,
            #[codec(default)]
            pub field2: u32,
        }
    };

    let token_stream = expand(syn::parse_quote!(OnlyDefaultsBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Unit struct
// === === === === === === === === === ===

#[test]
fn snapshot_unit_struct_ok() {
    let derive_input = parse_quote! {
        struct Unit;
    };

    let token_stream = expand(syn::parse_quote!(UnitBox), derive_input).expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Error cases
// === === === === === === === === === ===

#[test]
fn snapshot_tuple_struct_fails() {
    let derive_input = parse_quote! {
        #[derive(Codec)]
        struct Data(Vec<u8>, u64, u32);
    };

    let result = expand(syn::parse_quote!(DataBox), derive_input);
    assert!(result.is_err());

    let err_str = format!("{}", result.unwrap_err());
    assert!(err_str.contains("named structs"));
}

#[test]
fn snapshot_enum_fails() {
    let derive_input = parse_quote! {
        enum Choice {
            Alpha,
            Beta,
        }
    };

    let result = expand(syn::parse_quote!(ChoiceBox), derive_input);
    assert!(result.is_err());

    let err_str = format!("{}", result.unwrap_err());
    assert!(err_str.contains("structs"));
}

#[test]
fn snapshot_union_fails() {
    let derive_input = parse_quote! {
        union MyUnion {
            f1: u32,
            f2: f32,
        }
    };

    let result = expand(syn::parse_quote!(MyUnionBox), derive_input);
    assert!(result.is_err());
}
