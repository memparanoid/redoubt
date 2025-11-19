// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, Index, LitStr, parse_macro_input};

/// Main derive function for `MemCodec`.
/// This function is called when using #[derive(MemCodec)] on a struct.
#[proc_macro_derive(MemCodec)]
pub fn derive_memcode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput); // Parse the input to DeriveInput
    expand(input).unwrap_or_else(|e| e).into() // Expand the input and convert it to TokenStream
}

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

    let preferred = candidates.first().copied().unwrap_or("memcode");
    let list = candidates
        .iter()
        .map(|s| format!("`{}`", s))
        .collect::<Vec<_>>()
        .join(", ");
    let preferred_dep = format!("`{} = {{ version = \"*\" }}`", preferred);
    let alt_dep = if candidates.len() > 1 {
        let alts = candidates
            .iter()
            .skip(1)
            .map(|s| format!("`{} = {{ version = \"*\" }}`", s))
            .collect::<Vec<_>>()
            .join(" or ");
        format!(" (preferred) or {}", alts)
    } else {
        String::new()
    };

    let msg = format!(
        "MemCodec: could not find any of the candidate crates: {}. Add {}{} to your Cargo.toml.",
        list, preferred_dep, alt_dep
    );
    let lit = LitStr::new(&msg, Span::call_site());
    quote! { compile_error!(#lit); }
}

/// Expands the DeriveInput into the necessary implementation of `MemCodec`.
fn expand(input: DeriveInput) -> Result<TokenStream2, TokenStream2> {
    let struct_name = &input.ident; // Name of the struct
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl(); // Get generics

    // 1) Resolving the `memcode` or `memcode_core` crate
    let root = find_root_with_candidates(&["memcode", "memcode_core"]);

    // 2) Collect references to the struct fields for the `MemCode` and `MemDecode` traits
    let (mut immut_refs, mut mut_refs): (Vec<TokenStream2>, Vec<TokenStream2>) =
        (Vec::new(), Vec::new());

    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => {
                for f in &named.named {
                    let ident = f.ident.as_ref().unwrap();

                    immut_refs.push(quote! { &self.#ident });
                    mut_refs.push(quote! { &mut self.#ident });
                }
            }
            Fields::Unnamed(unnamed) => {
                for (i, _f) in unnamed.unnamed.iter().enumerate() {
                    let idx = Index::from(i);
                    immut_refs.push(quote! { &self.#idx });
                    mut_refs.push(quote! { &mut self.#idx });
                }
            }
            Fields::Unit => {}
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "MemCodec can only be derived for structs (named or tuple).",
            )
            .to_compile_error());
        }
    };

    // 4) Specify lengths (it could be done with mut_refs also)
    let len = immut_refs.len();
    let len_lit = syn::LitInt::new(&len.to_string(), Span::call_site());

    // 5) Emit the traits implementations for the struct
    let output = quote! {
        impl #impl_generics #root::MemDrainEncode for #struct_name #ty_generics #where_clause {
          #[inline]
          fn mem_encode_required_capacity(&self) -> usize {
            let fields: [&dyn #root::MemDrainEncode; #len_lit] = [ #( #immut_refs ),* ];
            #root::utils::non_primitive::mem_encode_required_capacity(&fields)
          }

          #[inline]
          fn drain_into(&mut self, buf: &mut #root::WordBuf) -> Result<(), #root::MemEncodeError> {
            let mut fields: [&mut dyn #root::ZeroizableMemDrainEncode; #len_lit] = [ #( #mut_refs ),* ];
             #root::utils::non_primitive::drain_into(&mut fields, buf)
          }
        }

        impl #impl_generics #root::MemDrainDecode for #struct_name #ty_generics #where_clause {
              fn drain_from(&mut self, words: &mut [#root::MemCodeWord]) -> Result<(), #root::MemDecodeError> {
                    let mut fields: [&mut dyn #root::ZeroizableMemDrainDecode; #len_lit] = [ #( #mut_refs ),* ];
                    #root::utils::non_primitive::drain_from(fields.as_mut_slice(), words)
              }
        }
    };

    Ok(output) // Return the generated code
}
