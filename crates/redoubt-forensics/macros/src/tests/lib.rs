// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use proc_macro_crate::FoundCrate;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

use crate::{dirt, expand, forensics_path, named};

fn every_one_found(_: &str) -> Option<FoundCrate> {
    Some(FoundCrate::Itself)
}

fn only(wanted: &'static str, as_name: &'static str) -> impl Fn(&str) -> Option<FoundCrate> {
    move |name| (name == wanted).then(|| FoundCrate::Name(as_name.to_owned()))
}

fn same(left: TokenStream2, right: TokenStream2) {
    assert_eq!(left.to_string(), right.to_string());
}

// ============================================================================
// test
// ============================================================================

#[test]
#[ignore = "Reached from an expansion only: `proc_macro::TokenStream` cannot be made \
            outside one. The crate's integration tests use the attribute."]
fn test_test_expands_the_function_it_is_put_on() {
    // Intentionally empty.
}

// ============================================================================
// forensics_path
// ============================================================================

#[test]
fn test_forensics_path_reports_no_crate_to_reach() {
    let result = forensics_path(|_| None);

    assert!(result.is_err_and(|error| error.to_string().contains("is a dependency")));
}

#[test]
fn test_forensics_path_returns_redoubt_forensics_first() -> Result<(), syn::Error> {
    same(
        forensics_path(every_one_found)?,
        quote!(::redoubt_forensics),
    );

    Ok(())
}

#[test]
fn test_forensics_path_returns_the_facade_s_forensics_without_redoubt_forensics()
-> Result<(), syn::Error> {
    same(
        forensics_path(only("redoubt", "redoubt"))?,
        quote!(::redoubt::forensics),
    );

    Ok(())
}

#[test]
fn test_forensics_path_returns_redoubt_forensics_core_without_the_other_two()
-> Result<(), syn::Error> {
    same(
        forensics_path(only("redoubt-forensics-core", "redoubt_forensics_core"))?,
        quote!(::redoubt_forensics_core),
    );

    Ok(())
}

#[test]
fn test_forensics_path_returns_a_dependency_under_the_name_it_was_given() -> Result<(), syn::Error>
{
    same(
        forensics_path(only("redoubt-forensics", "renamed"))?,
        quote!(::renamed),
    );

    Ok(())
}

// ============================================================================
// named
// ============================================================================

#[test]
fn test_named_returns_the_crate_s_own_name_when_it_is_itself() {
    same(named(FoundCrate::Itself, "itself"), quote!(::itself));
}

#[test]
fn test_named_returns_the_name_the_dependency_was_given() {
    same(
        named(FoundCrate::Name("given".to_owned()), "itself"),
        quote!(::given),
    );
}

// ============================================================================
// dirt
// ============================================================================

#[test]
fn test_dirt_reports_an_argument_that_is_not_dirty() {
    let result = dirt(quote!(clean = 1));

    assert!(result.is_err_and(|error| error.to_string().contains("dirty = <byte>")));
}

#[test]
fn test_dirt_propagates_a_value_that_is_not_an_integer() {
    let result = dirt(quote!(dirty = "0xFF"));

    assert!(result.is_err_and(|error| error.to_string().contains("expected integer literal")));
}

#[test]
fn test_dirt_propagates_a_value_wider_than_a_byte() {
    let result = dirt(quote!(dirty = 256));

    assert!(result.is_err_and(|error| error.to_string().contains("too large")));
}

#[test]
fn test_dirt_returns_none_without_arguments() -> Result<(), syn::Error> {
    assert_eq!(dirt(quote!())?, None);

    Ok(())
}

#[test]
fn test_dirt_returns_the_byte_it_is_given() -> Result<(), syn::Error> {
    assert_eq!(dirt(quote!(dirty = 0xFC))?, Some(0xFC));

    Ok(())
}

// ============================================================================
// expand
// ============================================================================

#[test]
fn test_expand_propagates_dirt_error() {
    let result = expand(
        quote!(clean = 1),
        quote!(
            fn a() {}
        ),
        quote!(::f),
    );

    assert!(result.is_err_and(|error| error.to_string().contains("dirty = <byte>")));
}

#[test]
fn test_expand_propagates_an_item_that_is_not_a_function() {
    let result = expand(
        quote!(),
        quote!(
            struct A;
        ),
        quote!(::f),
    );

    assert!(result.is_err_and(|error| error.to_string().contains("expected `fn`")));
}

#[test]
fn test_expand_returns_a_test_that_enables_the_allocator_first() -> Result<(), syn::Error> {
    same(
        expand(
            quote!(),
            quote!(
                fn a() {
                    b();
                }
            ),
            quote!(::f),
        )?,
        quote! {
            #[test]
            fn a() {
                ::f::enable_forensics_allocator(::core::option::Option::None);

                { b(); }
            }
        },
    );

    Ok(())
}

#[test]
fn test_expand_returns_a_test_that_enables_the_allocator_with_its_dirt() -> Result<(), syn::Error> {
    same(
        expand(
            quote!(dirty = 0xFF),
            quote!(
                fn a() {}
            ),
            quote!(::f),
        )?,
        quote! {
            #[test]
            fn a() {
                ::f::enable_forensics_allocator(::core::option::Option::Some(255u8));

                {}
            }
        },
    );

    Ok(())
}

#[test]
fn test_expand_returns_the_function_s_attributes_and_signature_as_they_were()
-> Result<(), syn::Error> {
    let item = quote! {
        #[ignore = "why"]
        pub(crate) fn a() -> Result<(), E> { Ok(()) }
    };

    same(
        expand(quote!(), item, quote!(::f))?,
        quote! {
            #[ignore = "why"]
            #[test]
            pub(crate) fn a() -> Result<(), E> {
                ::f::enable_forensics_allocator(::core::option::Option::None);

                { Ok(()) }
            }
        },
    );

    Ok(())
}
