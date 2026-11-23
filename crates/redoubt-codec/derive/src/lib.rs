// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Procedural macros for redoubt-codec.
//!
//! ## License
//!
//! GPL-3.0-only

// Only run unit tests on architectures where insta (-> sha2 -> cpufeatures) compiles
#[cfg(all(
    test,
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "loongarch64"
    )
))]
mod tests;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{
    Attribute, Data, DeriveInput, Fields, Ident, Index, LitStr, Meta, Token, parse_macro_input,
};

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
/// Candidates can be crate names like "redoubt-codec" or paths like "redoubt::codec".
pub(crate) fn find_root_with_candidates(candidates: &[&'static str]) -> TokenStream2 {
    for &candidate in candidates {
        // Check if candidate contains "::" (path syntax like "redoubt::codec")
        if let Some((crate_part, path_part)) = candidate.split_once("::") {
            match crate_name(crate_part) {
                Ok(FoundCrate::Itself) => {
                    let path: TokenStream2 = path_part.parse().unwrap_or_else(|_| quote!());
                    return quote!(crate::#path);
                }
                Ok(FoundCrate::Name(name)) => {
                    let crate_id = Ident::new(&name, Span::call_site());
                    let path: TokenStream2 = path_part.parse().unwrap_or_else(|_| quote!());
                    return quote!(#crate_id::#path);
                }
                Err(_) => continue,
            }
        } else {
            match crate_name(candidate) {
                Ok(FoundCrate::Itself) => return quote!(crate),
                Ok(FoundCrate::Name(name)) => {
                    let id = Ident::new(&name, Span::call_site());
                    return quote!(#id);
                }
                Err(_) => continue,
            }
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

const INTEGER_REPRS: [&str; 12] = [
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
];

const TAG_REPRS: [&str; 4] = ["u8", "u16", "u32", "u64"];

fn repr_of(input: &DeriveInput) -> Option<Ident> {
    input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("repr"))
        .filter_map(|attr| {
            attr.parse_args_with(Punctuated::<Ident, Token![,]>::parse_terminated)
                .ok()
        })
        .flatten()
        .find(|ident| INTEGER_REPRS.iter().any(|integer| ident == integer))
}

fn tag_repr_of(input: &DeriveInput) -> Result<Ident, TokenStream2> {
    let repr = repr_of(input).ok_or_else(|| {
        syn::Error::new_spanned(
            &input.ident,
            "RedoubtCodec: an enum needs #[repr(u8)], #[repr(u16)], #[repr(u32)] or #[repr(u64)]: its tag on the wire.",
        )
        .to_compile_error()
    })?;

    if !TAG_REPRS.iter().any(|tag| repr == tag) {
        return Err(syn::Error::new_spanned(
            &repr,
            "RedoubtCodec: an enum's tag on the wire is u8, u16, u32 or u64.",
        )
        .to_compile_error());
    }

    Ok(repr)
}

fn variant_pattern(variant: &syn::Variant, bindings: &[TokenStream2]) -> TokenStream2 {
    let ident = &variant.ident;

    match &variant.fields {
        Fields::Named(named) => {
            let names = named.named.iter().map(|field| field.ident.as_ref());

            quote! { Self::#ident { #( #names: #bindings ),* } }
        }
        Fields::Unnamed(_) => quote! { Self::#ident( #( #bindings ),* ) },
        Fields::Unit => quote! { Self::#ident },
    }
}

fn variant_default(variant: &syn::Variant) -> TokenStream2 {
    let ident = &variant.ident;

    match &variant.fields {
        Fields::Named(named) => {
            let names = named.named.iter().map(|field| field.ident.as_ref());

            quote! { Self::#ident { #( #names: Default::default() ),* } }
        }
        Fields::Unnamed(unnamed) => {
            let defaults = unnamed
                .unnamed
                .iter()
                .map(|_| quote! { Default::default() });

            quote! { Self::#ident( #( #defaults ),* ) }
        }
        Fields::Unit => quote! { Self::#ident },
    }
}

fn expand_enum(
    input: &DeriveInput,
    data: &syn::DataEnum,
    root: &TokenStream2,
) -> Result<TokenStream2, TokenStream2> {
    let enum_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let repr = tag_repr_of(input)?;

    let mut bytes_required_arms = Vec::new();
    let mut encode_arms = Vec::new();
    let mut decode_variants = Vec::new();
    let mut decode_arms = Vec::new();

    for variant in &data.variants {
        let (_, tag) = variant.discriminant.as_ref().ok_or_else(|| {
            syn::Error::new_spanned(
                &variant.ident,
                "RedoubtCodec: every variant needs an explicit discriminant: it is its tag on the wire.",
            )
            .to_compile_error()
        })?;

        let mut bindings = Vec::new();
        let mut travelling = Vec::new();

        for (index, field) in variant.fields.iter().enumerate() {
            if has_codec_default(&field.attrs) {
                bindings.push(quote! { _ });
            } else {
                let binding = Ident::new(&format!("field_{index}"), Span::call_site());

                bindings.push(quote! { #binding });
                travelling.push(binding);
            }
        }

        let pattern = variant_pattern(variant, &bindings);
        let bindings = travelling;
        let default = variant_default(variant);
        let len_with_tag = syn::LitInt::new(&(bindings.len() + 1).to_string(), Span::call_site());
        let len = syn::LitInt::new(&bindings.len().to_string(), Span::call_site());

        bytes_required_arms.push(quote! {
            #pattern => {
                let tag: #repr = #tag;
                let fields: [&dyn #root::BytesRequired; #len_with_tag] = [
                    #root::collections::helpers::to_bytes_required_dyn_ref(&tag),
                    #( #root::collections::helpers::to_bytes_required_dyn_ref(#bindings) ),*
                ];
                #root::collections::helpers::bytes_required_sum(fields.into_iter())
            }
        });

        encode_arms.push(quote! {
            #pattern => {
                let mut tag: #repr = #tag;
                let fields: [&mut dyn #root::EncodeZeroize; #len_with_tag] = [
                    #root::collections::helpers::to_encode_zeroize_dyn_mut(&mut tag),
                    #( #root::collections::helpers::to_encode_zeroize_dyn_mut(#bindings) ),*
                ];
                #root::collections::helpers::encode_fields(fields.into_iter(), buf)
            }
        });

        decode_variants.push(quote! {
            if tag == (#tag) {
                #default
            }
        });

        decode_arms.push(quote! {
            #pattern => {
                let fields: [&mut dyn #root::DecodeZeroize; #len] = [
                    #( #root::collections::helpers::to_decode_zeroize_dyn_mut(#bindings) ),*
                ];
                #root::collections::helpers::decode_fields(fields.into_iter(), buf)
            }
        });
    }

    Ok(quote! {
        impl #impl_generics #root::BytesRequired for #enum_name #ty_generics #where_clause {
            fn encode_bytes_required(&self) -> Result<usize, #root::OverflowError> {
                match self {
                    #( #bytes_required_arms )*
                }
            }
        }

        impl #impl_generics #root::Encode for #enum_name #ty_generics #where_clause {
            fn encode_into(&mut self, buf: &mut #root::RedoubtCodecBuffer) -> Result<(), #root::EncodeError> {
                match self {
                    #( #encode_arms )*
                }
            }
        }

        impl #impl_generics #root::Decode for #enum_name #ty_generics #where_clause {
            fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), #root::DecodeError> {
                let mut tag: #repr = 0;
                let tag_field: [&mut dyn #root::DecodeZeroize; 1] = [
                    #root::collections::helpers::to_decode_zeroize_dyn_mut(&mut tag),
                ];

                #root::collections::helpers::decode_fields(tag_field.into_iter(), buf)?;

                #root::collections::helpers::fast_zeroize_decode_zeroize(
                    #root::collections::helpers::to_decode_zeroize_dyn_mut(self),
                );

                *self = #( #decode_variants else )* {
                    return Err(#root::DecodeError::UnknownTag { tag: u64::from(tag) });
                };

                match self {
                    #( #decode_arms )*
                }
            }
        }
    })
}

fn expand(input: DeriveInput) -> Result<TokenStream2, TokenStream2> {
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let root =
        find_root_with_candidates(&["redoubt-codec-core", "redoubt-codec", "redoubt::codec"]);

    // Get fields
    let fields: Vec<(usize, &syn::Field)> = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => named.named.iter().enumerate().collect(),
            Fields::Unnamed(unnamed) => unnamed.unnamed.iter().enumerate().collect(),
            Fields::Unit => vec![],
        },
        Data::Enum(data) => return expand_enum(&input, data, &root),
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
