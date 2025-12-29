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
    let ts_3 = find_root_with_candidates(&["redoubt-vault-derive", "redoubt-vault-core"]);
    println!("{:?}", ts_3);
    assert_eq!(format!("{:?}", ts_3), "TokenStream [Ident { sym: crate }]");

    let ts_4 = find_root_with_candidates(&["redoubt-vault-core", "redoubt-vault-derive"]);
    println!("{:?}", ts_4);
    assert_eq!(
        format!("{:?}", ts_4),
        "TokenStream [Ident { sym: redoubt_vault_core }]"
    );
}

// === === === === === === === === === ===
// Named structs - Basic
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_ok() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero, RedoubtCodec)]
        struct Data {
            pub alpha: Vec<u8>,
            pub beta: u64,
        }
    };

    let token_stream = expand(
        syn::parse_quote!(DataBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_single_field() {
    let derive_input = parse_quote! {
        struct Gamma {
            pub value: [u8; 32],
        }
    };

    let token_stream = expand(
        syn::parse_quote!(GammaBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_generics() {
    let derive_input = parse_quote! {
        struct Container<T> where T: redoubt_codec::BytesRequired + redoubt_codec::Encode + redoubt_codec::Decode {
            pub value: T,
            pub count: u64,
        }
    };

    let token_stream = expand(
        syn::parse_quote!(ContainerBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_custom_error() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero, RedoubtCodec)]
        struct WithCustomError {
            pub field1: Vec<u8>,
            pub field2: u64,
        }
    };

    let custom_error: syn::Type = syn::parse_quote!(MyCustomError);
    let token_stream = expand(
        syn::parse_quote!(WithCustomErrorBox),
        Some(custom_error),
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Named structs - Field filtering
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_with_codec_default_field() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero, RedoubtCodec)]
        struct Delta {
            pub alpha: Vec<u8>,
            pub beta: [u8; 32],
            #[codec(default)]
            pub gamma: [u8; 16],
        }
    };

    let token_stream = expand(
        syn::parse_quote!(DeltaBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_zeroize_on_drop_sentinel() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero, RedoubtCodec)]
        #[fast_zeroize(drop)]
        struct Epsilon {
            pub master_seed: [u8; 32],
            pub encryption_key: [u8; 32],
            #[codec(default)]
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(
        syn::parse_quote!(EpsilonBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

#[test]
fn snapshot_named_struct_with_multiple_filtered_fields() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero, RedoubtCodec)]
        struct Zeta {
            pub field1: Vec<u8>,
            #[codec(default)]
            pub field2: [u8; 32],
            pub field3: u64,
            __sentinel: ZeroizeOnDropSentinel,
            #[codec(default)]
            pub field4: u32,
        }
    };

    let token_stream = expand(
        syn::parse_quote!(ZetaBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Named structs - Edge cases
// === === === === === === === === === ===

#[test]
fn snapshot_empty_struct_with_only_sentinel() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero)]
        struct Empty {
            #[codec(default)]
            __sentinel: ZeroizeOnDropSentinel,
        }
    };

    let token_stream = expand(
        syn::parse_quote!(EmptyBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
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

    let token_stream = expand(
        syn::parse_quote!(OnlyDefaultsBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
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

    let token_stream = expand(
        syn::parse_quote!(UnitBox),
        None,
        false,
        None,
        None,
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}

// === === === === === === === === === ===
// Error cases
// === === === === === === === === === ===

#[test]
fn snapshot_tuple_struct_fails() {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Data(Vec<u8>, u64, u32);
    };

    let result = expand(
        syn::parse_quote!(DataBox),
        None,
        false,
        None,
        None,
        derive_input,
    );
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

    let result = expand(
        syn::parse_quote!(ChoiceBox),
        None,
        false,
        None,
        None,
        derive_input,
    );
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

    let result = expand(
        syn::parse_quote!(MyUnionBox),
        None,
        false,
        None,
        None,
        derive_input,
    );
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "cipherbox: unknown attribute parameter")]
fn test_unknown_attribute_panics() {
    let _ = crate::parse_cipherbox_attr_inner("DataBox, foo = \"bar\"".to_string());
}

#[test]
fn test_parse_testing_feature() {
    let (name, error, global, storage, testing_feature) = crate::parse_cipherbox_attr_inner(
        "SecretsBox, testing_feature = \"test-utils\"".to_string(),
    );

    assert_eq!(name.to_string(), "SecretsBox");
    assert!(error.is_none());
    assert!(!global);
    assert!(storage.is_none());
    assert_eq!(testing_feature, Some("test-utils".to_string()));
}

// === === === === === === === === === ===
// testing_feature attribute
// === === === === === === === === === ===

#[test]
fn snapshot_named_struct_with_testing_feature() {
    let derive_input = parse_quote! {
        #[derive(RedoubtZero, RedoubtCodec)]
        struct TestableSecrets {
            pub secret_key: [u8; 32],
        }
    };

    let token_stream = expand(
        syn::parse_quote!(TestableSecretsBox),
        None,
        false,
        None,
        Some("test-utils".to_string()),
        derive_input,
    )
    .expect("expand failed");
    insta::assert_snapshot!(pretty(token_stream));
}
