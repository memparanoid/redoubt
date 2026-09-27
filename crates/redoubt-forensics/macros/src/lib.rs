// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The test attribute a forensics test is written with.

#[cfg(test)]
mod tests;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::meta::ParseNestedMeta;
use syn::parse::Parser;
use syn::{Ident, ItemFn, LitInt};

/// Every crate that exports the allocator: the dependency's name, its own name
/// inside itself, and the path to the allocator within it. The first one the
/// caller depends on is the one reached.
const REACHES: [(&str, &str, &[&str]); 3] = [
    ("redoubt-forensics", "redoubt_forensics", &[]),
    ("redoubt", "redoubt", &["forensics"]),
    ("redoubt-forensics-core", "redoubt_forensics_core", &[]),
];

/// A `#[test]` whose first statement turns the forensics allocator on, filling
/// what it hands out with the byte `dirty = <byte>` names, when there is one.
#[proc_macro_attribute]
pub fn test(args: TokenStream, item: TokenStream) -> TokenStream {
    forensics_path(&|name| crate_name(name).ok())
        .and_then(|forensics| expand(args.into(), item.into(), forensics))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The path the expansion reaches the allocator through, from whichever of the
/// crates that export it the caller depends on.
fn forensics_path(find: &dyn Fn(&str) -> Option<FoundCrate>) -> Result<TokenStream2, syn::Error> {
    REACHES
        .iter()
        .find_map(|(dependency, itself, within)| {
            find(dependency).map(|found| {
                let reached = named(found, itself);
                let within = within
                    .iter()
                    .map(|segment| Ident::new(segment, Span::call_site()));

                quote!(#reached #(::#within)*)
            })
        })
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "none of redoubt-forensics, redoubt or redoubt-forensics-core is a dependency",
            )
        })
}

/// The crate as the caller reaches it: the name its dependency goes by, or
/// `itself` inside that crate.
fn named(found: FoundCrate, itself: &str) -> TokenStream2 {
    let name = match found {
        // Resolves inside that crate only if it declares `extern crate self as
        // <itself>;`, and fails to compile where it does not.
        FoundCrate::Itself => itself.to_owned(),
        FoundCrate::Name(name) => name,
    };

    let name = Ident::new(&name, Span::call_site());

    quote!(::#name)
}

fn dirt(args: TokenStream2) -> Result<Option<u8>, syn::Error> {
    let mut dirt = None;

    let parser = syn::meta::parser(|meta| {
        dirt = Some(dirty_byte(meta)?);

        Ok(())
    });

    parser.parse2(args)?;

    Ok(dirt)
}

fn dirty_byte(meta: ParseNestedMeta<'_>) -> Result<u8, syn::Error> {
    if !meta.path.is_ident("dirty") {
        return Err(meta.error("the only argument is `dirty = <byte>`"));
    }

    let byte: LitInt = meta.value()?.parse()?;

    byte.base10_parse()
}

fn expand(
    args: TokenStream2,
    item: TokenStream2,
    forensics: TokenStream2,
) -> Result<TokenStream2, syn::Error> {
    let dirt = dirt(args)?.map_or_else(
        || quote!(::core::option::Option::None),
        |byte| quote!(::core::option::Option::Some(#byte)),
    );

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = syn::parse2(item)?;

    Ok(quote! {
        #(#attrs)*
        #[test]
        #vis #sig {
            #forensics::enable_forensics_allocator(#dirt);

            #block
        }
    })
}
