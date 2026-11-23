// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use rstest::rstest;
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

/// The expansion, pretty-printed, with a refusal carried as its own text.
///
/// What `expand` refuses with is the `compile_error!` it would have emitted,
/// which is a `TokenStream` and so not an error `?` can carry. Its text is
/// what a reader wants anyway.
fn expanded(input: syn::DeriveInput) -> Result<String, Box<dyn std::error::Error>> {
    expand(input)
        .map(pretty)
        .map_err(|refusal| refusal.to_string().into())
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
fn snapshot_named_struct_ok() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Data {
            pub alpha: Vec<u8>,
            pub beta: u64,
        }
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}

#[test]
fn snapshot_tuple_struct_ok() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Data(Vec<u8>, u64, u32);
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}

#[test]
fn snapshot_unit_struct_ok() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Empty;
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}

#[test]
fn snapshot_struct_with_generics_ok() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Container<T> where T: redoubt_codec::BytesRequired + redoubt_codec::Encode + redoubt_codec::Decode {
            pub value: T,
            pub count: u64,
        }
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}

// enums

#[test]
fn snapshot_enum_ok() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        #[repr(u8)]
        enum Choice {
            Alpha = 0,
            Beta([u8; 16], #[codec(default)] u64) = 1,
            Gamma { key: [u8; 32], #[codec(default)] count: u64, id: u64 } = 2,
        }
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}

#[test]
fn test_expand_reports_an_enum_without_a_repr() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        enum Choice {
            A = 0,
            B = 1,
        }
    };

    let refusal = expand(derive_input)
        .err()
        .ok_or("an enum without a repr was expanded")?;

    assert_eq!(
        refusal.to_string(),
        ":: core :: compile_error ! { \"RedoubtCodec: an enum needs #[repr(u8)], #[repr(u16)], #[repr(u32)] or #[repr(u64)]: its tag on the wire.\" }"
    );

    Ok(())
}

#[test]
fn test_expand_reports_an_enum_whose_repr_names_no_integer()
-> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        #[repr(C)]
        enum Choice {
            A = 0,
            B = 1,
        }
    };

    let refusal = expand(derive_input)
        .err()
        .ok_or("an enum whose repr names no integer was expanded")?;

    assert_eq!(
        refusal.to_string(),
        ":: core :: compile_error ! { \"RedoubtCodec: an enum needs #[repr(u8)], #[repr(u16)], #[repr(u32)] or #[repr(u64)]: its tag on the wire.\" }"
    );

    Ok(())
}

#[rstest]
#[case::u128(parse_quote!(u128))]
#[case::usize(parse_quote!(usize))]
#[case::i8(parse_quote!(i8))]
#[case::i16(parse_quote!(i16))]
#[case::i32(parse_quote!(i32))]
#[case::i64(parse_quote!(i64))]
#[case::i128(parse_quote!(i128))]
#[case::isize(parse_quote!(isize))]
fn test_expand_reports_an_enum_whose_tag_is_not_a_wire_tag(
    #[case] repr: syn::Ident,
) -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        #[repr(#repr)]
        enum Choice {
            A = 0,
            B = 1,
        }
    };

    let refusal = expand(derive_input)
        .err()
        .ok_or("an enum whose tag is not a wire tag was expanded")?;

    assert_eq!(
        refusal.to_string(),
        ":: core :: compile_error ! { \"RedoubtCodec: an enum's tag on the wire is u8, u16, u32 or u64.\" }"
    );

    Ok(())
}

#[test]
fn test_expand_reports_a_variant_without_a_discriminant() -> Result<(), Box<dyn std::error::Error>>
{
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        #[repr(u8)]
        enum Choice {
            A = 0,
            B,
        }
    };

    let refusal = expand(derive_input)
        .err()
        .ok_or("a variant without a discriminant was expanded")?;

    assert_eq!(
        refusal.to_string(),
        ":: core :: compile_error ! { \"RedoubtCodec: every variant needs an explicit discriminant: it is its tag on the wire.\" }"
    );

    Ok(())
}

#[rstest]
#[case::u8(parse_quote!(u8))]
#[case::u16(parse_quote!(u16))]
#[case::u32(parse_quote!(u32))]
#[case::u64(parse_quote!(u64))]
fn test_expand_returns_an_enum_whose_tag_is_a_wire_tag(#[case] repr: syn::Ident) {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        #[repr(#repr)]
        enum Choice {
            A = 0,
            B = 1,
        }
    };

    let expansion = expand(derive_input);

    assert!(expansion.is_ok());
}

#[test]
fn test_expand_returns_an_enum_whose_repr_also_names_c() {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        #[repr(C, u8)]
        enum Choice {
            A = 0,
            B = 1,
        }
    };

    let expansion = expand(derive_input);

    assert!(expansion.is_ok());
}

// #[codec(default)]

#[test]
fn snapshot_named_struct_ok_with_codec_default() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Sigma {
            pub alpha: Vec<u8>,
            pub beta: [u8; 32],
            #[codec(default)]
            pub gamma: [u8; 16],
        }
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}

#[test]
fn snapshot_tuple_struct_ok_with_codec_default() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Sigma(Vec<u8>, [u8; 32], #[codec(default)] [u8; 16]);
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}

#[test]
fn snapshot_named_struct_with_non_default_codec_attr() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Sigma {
            pub alpha: Vec<u8>,
            #[codec(skip)]
            pub beta: [u8; 32],
        }
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}

#[test]
fn snapshot_named_struct_with_other_list_attr() -> Result<(), Box<dyn std::error::Error>> {
    let derive_input = parse_quote! {
        #[derive(RedoubtCodec)]
        struct Sigma {
            pub alpha: Vec<u8>,
            #[serde(default)]
            pub beta: [u8; 32],
        }
    };

    insta::assert_snapshot!(expanded(derive_input)?);

    Ok(())
}
