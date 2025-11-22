// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Procedural macros for the `memzer` crate.
//!
//! Provides the `#[derive(MemZer)]` macro for automatic trait implementations.

#![warn(missing_docs)]

#[cfg(test)]
mod tests;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Ident, Index, LitStr, Type, parse_macro_input};

/// Derives `Zeroizable`, `ZeroizationProbe`, and `AssertZeroizeOnDrop` for a struct.
///
/// This macro automatically generates trait implementations for structs that contain
/// a `DropSentinel` field.
///
/// # Requirements
///
/// - The struct must derive `Zeroize` and use `#[zeroize(drop)]`
/// - Named structs must have a field named `__drop_sentinel: DropSentinel`
/// - Tuple structs must have a field of type `DropSentinel`
///
/// # Example
///
/// ```rust
/// use memzer_derive::MemZer;
/// use memzer_core::{DropSentinel, Zeroizable, ZeroizationProbe};
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize, MemZer)]
/// #[zeroize(drop)]
/// struct ApiKey {
///     key: Vec<u8>,
///     __drop_sentinel: DropSentinel,
/// }
/// ```
#[proc_macro_derive(MemZer)]
pub fn derive_memzer(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(input).unwrap_or_else(|e| e).into()
}

/// Finds the root crate path from a list of candidates.
///
/// Resolves the correct import path for `memzer` or `memzer-core` depending on context.
pub(crate) fn find_root_with_candidates(candidates: &[&'static str]) -> TokenStream2 {
    for &candidate in candidates {
        match crate_name(candidate) {
            Ok(FoundCrate::Itself) => return quote!(crate),
            Ok(FoundCrate::Name(name)) => {
                let id = Ident::new(&name, Span::call_site());
                return quote!(#id);
            }
            Err(_) => continue,
        }
    }

    let preferred = candidates.first().copied().unwrap_or("memzer");
    let list = candidates
        .iter()
        .map(|s| format!("`{}`", s))
        .collect::<Vec<_>>()
        .join(", ");
    let preferred_dep = format!("`{} = {{ version = \\\"*\\\" }}`", preferred);
    let alt_dep = if candidates.len() > 1 {
        let alts = candidates
            .iter()
            .skip(1)
            .map(|s| format!("`{} = {{ version = \\\"*\\\" }}`", s))
            .collect::<Vec<_>>()
            .join(" or ");
        format!(" (preferred) or {}", alts)
    } else {
        String::new()
    };

    let msg = format!(
        "MemZer: could not find any of the candidate crates: {}. Add {}{} to your Cargo.toml.",
        list, preferred_dep, alt_dep
    );
    let lit = LitStr::new(&msg, Span::call_site());
    quote! { compile_error!(#lit); }
}

/// Detects if a type is `DropSentinel` by checking the type path.
///
/// Used for tuple struct support where we identify the sentinel field by type.
pub(crate) fn is_drop_sentinel_type(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Path(type_path)
        if type_path.path.segments.last()
            .map(|seg| seg.ident == "DropSentinel")
            .unwrap_or(false)
    )
}

/// Expands the DeriveInput into the necessary implementation of `MemZer`.
fn expand(input: DeriveInput) -> Result<TokenStream2, TokenStream2> {
    let struct_name = &input.ident; // Name of the struct
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl(); // Get generics

    // 1) Resolving the `memzer` or `memzer_core` crate
    let root = find_root_with_candidates(&["memzer", "memzer_core"]);

    // 2) Collect references to the struct fields, skipping __drop_sentinel
    let sentinel_ident = format_ident!("__drop_sentinel");
    let mut drop_sentinel_field_found = false;
    let mut drop_sentinel_access: Option<TokenStream2> = None;
    let mut immut_refs: Vec<TokenStream2> = Vec::new();

    match &input.data {
        Data::Struct(data) => {
            match &data.fields {
                Fields::Named(named) => {
                    for f in &named.named {
                        let ident = f.ident.as_ref().unwrap();

                        if *ident == sentinel_ident {
                            drop_sentinel_field_found = true;
                            drop_sentinel_access = Some(quote! { self.#sentinel_ident });
                            continue;
                        }

                        immut_refs.push(quote! { #root::collections::to_zeroization_probe_dyn_ref(&self.#ident) });
                    }
                }
                Fields::Unnamed(unnamed) => {
                    for (i, f) in unnamed.unnamed.iter().enumerate() {
                        // Detect DropSentinel by type in tuple structs
                        if is_drop_sentinel_type(&f.ty) {
                            drop_sentinel_field_found = true;
                            let idx = Index::from(i);
                            drop_sentinel_access = Some(quote! { self.#idx });
                            continue;
                        }

                        let idx = Index::from(i);
                        immut_refs.push(
                            quote! { #root::collections::to_zeroization_probe_dyn_ref(&self.#idx) },
                        );
                    }
                }
                Fields::Unit => {}
            }
        }
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "MemZer can only be derived for structs (named or tuple).",
            )
            .to_compile_error());
        }
    };

    if !drop_sentinel_field_found {
        return Err(syn::Error::new_spanned(
            struct_name,
            "MemZer: missing field `__drop_sentinel` (named structs) or field of type `DropSentinel` (tuple structs)",
        )
        .to_compile_error());
    }

    // 3) Specify lengths
    let len = immut_refs.len();
    let len_lit = syn::LitInt::new(&len.to_string(), Span::call_site());

    // Get the sentinel access (either self.__drop_sentinel or self.N)
    let sentinel_access = drop_sentinel_access.unwrap();

    // 4) Emit the trait implementations for the struct
    let output = quote! {
        impl #impl_generics #root::Zeroizable for #struct_name #ty_generics #where_clause {
            fn self_zeroize(&mut self) {
                self.zeroize();
            }
        }

        impl #impl_generics #root::ZeroizationProbe for #struct_name #ty_generics #where_clause {
            fn is_zeroized(&self) -> bool {
                let fields: [&dyn #root::ZeroizationProbe; #len_lit] = [
                    #( #immut_refs ),*
                ];
                // `fields.into_iter()` produces &dyn ZeroizationProbe directly,
                // avoiding the double reference (&&) that `.iter()` would create.
                // No values are copied - we're just iterating over references from the array.
                #root::collections::collection_zeroed(&mut fields.into_iter())
            }
        }

        impl #impl_generics #root::AssertZeroizeOnDrop for #struct_name #ty_generics #where_clause {
            fn clone_drop_sentinel(&self) -> #root::drop_sentinel::DropSentinel {
                #sentinel_access.clone()
            }

            fn assert_zeroize_on_drop(self) {
                #root::assert::assert_zeroize_on_drop(self);
            }
        }
    };

    Ok(output) // Return the generated code
}
