// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Procedural macros for redoubt-codec.
//!
//! ## License
//!
//! GPL-3.0-only

// Only run unit tests on architectures where insta (-> sha2 -> cpufeatures) compiles
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64", target_arch = "loongarch64")))]
mod tests;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Attribute, Data, DeriveInput, Fields, Ident, Index, LitStr, Meta, parse_macro_input};

/// Derives `BytesRequired`, `Encode`, and `Decode` for a struct.
///
/// # Attributes
///
/// - `#[codec(default)]` on a field: Skip encoding/decoding, use `Default::default()`
#[proc_macro_derive(RedoubtCodec, attributes(codec))]
pub fn derive_redoubt_codec(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(input).unwrap_or_else(|e| e).into()
}

/// Find the root crate path from a list of candidates.
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

    let msg = "RedoubtCodec: could not find redoubt-codec or redoubt-codec-core. Add redoubt-codec to Cargo.toml.";
    let lit = LitStr::new(msg, Span::call_site());
    quote! { compile_error!(#lit); }
}

/// Checks if a field has the `#[codec(default)]` attribute.
fn has_codec_default(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        matches!(&attr.meta, Meta::List(meta_list)
            if meta_list.path.is_ident("codec")
            && meta_list.tokens.to_string().contains("default"))
    })
}

fn expand(input: DeriveInput) -> Result<TokenStream2, TokenStream2> {
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let root = find_root_with_candidates(&["redoubt-codec-core", "redoubt-codec", "redoubt"]);

    // Get fields
    let fields: Vec<(usize, &syn::Field)> = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => named.named.iter().enumerate().collect(),
            Fields::Unnamed(unnamed) => unnamed.unnamed.iter().enumerate().collect(),
            Fields::Unit => vec![],
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "RedoubtCodec can only be derived for structs.",
            )
            .to_compile_error());
        }
    };

    // Generate field references (filter out fields with #[codec(default)])
    let (immut_refs, mut_refs): (Vec<TokenStream2>, Vec<TokenStream2>) = fields
        .iter()
        .filter(|(_, f)| !has_codec_default(&f.attrs))
        .map(|(i, f)| {
            if let Some(ident) = &f.ident {
                (quote! { &self.#ident }, quote! { &mut self.#ident })
            } else {
                let idx = Index::from(*i);
                (quote! { &self.#idx }, quote! { &mut self.#idx })
            }
        })
        .unzip();

    let len = immut_refs.len();
    let len_lit = syn::LitInt::new(&len.to_string(), Span::call_site());

    let output = quote! {
        impl #impl_generics #root::BytesRequired for #struct_name #ty_generics #where_clause {
            fn encode_bytes_required(&self) -> Result<usize, #root::OverflowError> {
                let fields: [&dyn #root::BytesRequired; #len_lit] = [
                    #( #root::collections::helpers::to_bytes_required_dyn_ref(#immut_refs) ),*
                ];
                #root::collections::helpers::bytes_required_sum(fields.into_iter())
            }
        }

        impl #impl_generics #root::Encode for #struct_name #ty_generics #where_clause {
            fn encode_into(&mut self, buf: &mut #root::RedoubtCodecBuffer) -> Result<(), #root::EncodeError> {
                let fields: [&mut dyn #root::EncodeZeroize; #len_lit] = [
                    #( #root::collections::helpers::to_encode_zeroize_dyn_mut(#mut_refs) ),*
                ];
                #root::collections::helpers::encode_fields(fields.into_iter(), buf)
            }
        }

        impl #impl_generics #root::Decode for #struct_name #ty_generics #where_clause {
            fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), #root::DecodeError> {
                let fields: [&mut dyn #root::DecodeZeroize; #len_lit] = [
                    #( #root::collections::helpers::to_decode_zeroize_dyn_mut(#mut_refs) ),*
                ];
                #root::collections::helpers::decode_fields(fields.into_iter(), buf)
            }
        }
    };

    Ok(output)
}
