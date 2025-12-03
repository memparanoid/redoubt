// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Procedural macros for the `memcode` crate.
//!
//! Provides the `#[derive(MemCodec)]` macro for automatic trait implementations.

#![warn(missing_docs)]

#[cfg(test)]
mod tests;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Attribute, Data, DeriveInput, Fields, Ident, Index, LitStr, Meta, parse_macro_input};

/// Derives encoding and decoding traits for a struct.
///
/// This macro automatically generates trait implementations for structs to enable
/// allocation-free, zeroizing serialization via `memcode-core`.
///
/// # Generated Implementations
///
/// The macro generates the following trait implementations:
/// - [`FastZeroizable`](https://docs.rs/memcode-core/latest/memcode_core/trait.FastZeroizable.html)
/// - [`MemNumElements`](https://docs.rs/memcode-core/latest/memcode_core/trait.MemNumElements.html)
/// - [`MemBytesRequired`](https://docs.rs/memcode-core/latest/memcode_core/trait.MemBytesRequired.html)
/// - [`MemEncode`](https://docs.rs/memcode-core/latest/memcode_core/trait.MemEncode.html)
/// - [`MemDecode`](https://docs.rs/memcode-core/latest/memcode_core/trait.MemDecode.html)
/// - [`EncodeIterator`](https://docs.rs/memcode-core/latest/memcode_core/trait.EncodeIterator.html)
/// - [`DecodeIterator`](https://docs.rs/memcode-core/latest/memcode_core/trait.DecodeIterator.html)
/// - [`MemEncodable`](https://docs.rs/memcode-core/latest/memcode_core/trait.MemEncodable.html) (marker)
/// - [`MemDecodable`](https://docs.rs/memcode-core/latest/memcode_core/trait.MemDecodable.html) (marker)
/// - [`CollectionEncode`](https://docs.rs/memcode-core/latest/memcode_core/trait.CollectionEncode.html) (marker)
/// - [`CollectionDecode`](https://docs.rs/memcode-core/latest/memcode_core/trait.CollectionDecode.html)
///
/// # Requirements
///
/// - The struct must derive `Zeroize` and use `#[zeroize(drop)]`
/// - All fields must implement `MemEncodable` and `MemDecodable`
/// - Works with named structs, tuple structs, and unit structs
///
/// # Example (Named Struct)
///
/// ```rust
/// use memcode_derive::MemCodec;
/// use memcode_core::{MemEncodable, MemDecodable};
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize, MemCodec)]
/// #[zeroize(drop)]
/// struct Data {
///     field_a: Vec<u8>,
///     field_b: [u8; 32],
///     field_c: u64,
/// }
/// ```
///
/// # Example (Tuple Struct)
///
/// ```rust
/// use memcode_derive::MemCodec;
/// use memcode_core::{MemEncodable, MemDecodable};
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize, MemCodec)]
/// #[zeroize(drop)]
/// struct Data(Vec<u8>, [u8; 32], u64);
/// ```
///
/// # Example (With Generics)
///
/// ```rust
/// use memcode_derive::MemCodec;
/// use memcode_core::{MemEncodable, MemDecodable};
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize, MemCodec)]
/// #[zeroize(drop)]
/// struct Data<T: MemEncodable + MemDecodable + Zeroize> {
///     value: T,
///     metadata: u64,
/// }
/// ```
///
/// # Wire Format
///
/// Structs encode as collections with this format:
///
/// ```text
/// [ num_elements: usize LE ] [ bytes_required: usize LE ] [ field1 ] [ field2 ] ... [ fieldN ]
/// ```
///
/// # Error Handling
///
/// Generated implementations handle errors systematically:
/// - Encoding errors → source struct is zeroized
/// - Decoding errors → consumed bytes are zeroized
/// - Collection size mismatch → `MemDecodeError::LengthMismatch`
///
/// # Attributes
///
/// - `#[memcode(default)]` on a field: Skip encoding/decoding, use `Default::default()`
#[proc_macro_derive(MemCodec, attributes(memcode))]
pub fn derive_memcode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(input).unwrap_or_else(|e| e).into()
}

/// Finds the root crate path from a list of candidates.
///
/// Resolves the correct import path for `memcode` or `memcode-core` depending on context.
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

/// Checks if a field has the `#[memcode(default)]` attribute.
fn has_memcode_default(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        matches!(&attr.meta, Meta::List(meta_list)
            if meta_list.path.is_ident("memcode")
            && meta_list.tokens.to_string().contains("default"))
    })
}

/// Expands the `DeriveInput` into trait implementations for `MemCodec`.
///
/// This function generates all necessary trait implementations for encoding/decoding
/// the struct. It collects field references (both immutable and mutable) and generates
/// implementations that iterate over fields via collection helpers.
fn expand(input: DeriveInput) -> Result<TokenStream2, TokenStream2> {
    let struct_name = &input.ident; // Name of the struct
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl(); // Get generics

    // 1) Resolving the `memcode` or `memcode_core` crate
    let root = find_root_with_candidates(&["memcode_core", "memcode"]);

    // 2) Collect references to the struct fields for the `MemCode` and `MemDecode` traits
    // Skip fields with #[memcode(default)] - they keep their Default::default() value

    // Get fields as a Vec for functional processing
    let fields: Vec<(usize, &syn::Field)> = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => named.named.iter().enumerate().collect(),
            Fields::Unnamed(unnamed) => unnamed.unnamed.iter().enumerate().collect(),
            Fields::Unit => vec![],
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "MemCodec can only be derived for structs (named or tuple).",
            )
            .to_compile_error());
        }
    };

    // Functional approach: filter and map in one pass
    let (immut_refs, mut_refs): (Vec<TokenStream2>, Vec<TokenStream2>) = fields
        .iter()
        .filter(|(_, f)| !has_memcode_default(&f.attrs))
        .map(|(i, f)| {
            if let Some(ident) = &f.ident {
                // Named field
                (quote! { &self.#ident }, quote! { &mut self.#ident })
            } else {
                // Unnamed field (tuple)
                let idx = Index::from(*i);
                (quote! { &self.#idx }, quote! { &mut self.#idx })
            }
        })
        .unzip();

    // 4) Specify lengths (it could be done with mut_refs also)
    let len = immut_refs.len();
    let len_lit = syn::LitInt::new(&len.to_string(), Span::call_site());

    // 5) Emit the traits implementations for the struct
    let output = quote! {
        impl #impl_generics #root::FastZeroizable for #struct_name #ty_generics #where_clause {
            #[inline(always)]
            fn self_zeroize(&mut self) {
                self.zeroize();
            }
        }

        impl #impl_generics #root::MemNumElements for #struct_name #ty_generics #where_clause {
            #[inline(always)]
            fn mem_num_elements(&self) -> usize {
                #len_lit
            }
        }


        impl #impl_generics #root::MemBytesRequired for #struct_name #ty_generics #where_clause {
            fn mem_bytes_required(&self) -> Result<usize, #root::OverflowError> {
                let collection: [&dyn #root::MemBytesRequired; #len_lit] = [
                  #( #root::collections::to_bytes_required_dyn_ref(#immut_refs) ),*
                ];

                // `collection.into_iter()` produces &dyn MemBytesRequired directly,
                // avoiding the double reference (&&) that `.iter()` would create.
                // No values are copied - we're just iterating over references from the array.
                #root::collections::mem_bytes_required(&mut collection.into_iter())
            }
        }

        impl #impl_generics #root::MemEncode for #struct_name #ty_generics #where_clause {
            fn drain_into(&mut self, buf: &mut #root::MemEncodeBuf) -> Result<(), #root::MemEncodeError> {
                #root::collections::drain_into(buf, self)
            }
        }

        impl #impl_generics #root::MemDecode for #struct_name #ty_generics #where_clause {
            fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, #root::MemDecodeError> {
              #root::collections::drain_from(bytes, self)
            }
        }

        impl #impl_generics #root::DecodeIterator for #struct_name #ty_generics #where_clause {
          fn decode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn #root::MemDecodable> {
              let collection: [&mut dyn #root::MemDecodable; #len_lit] = [
                #( #root::collections::to_decode_dyn_mut(#mut_refs) ),*
              ];
              collection.into_iter()
          }
        }

        impl #impl_generics #root::EncodeIterator for #struct_name #ty_generics #where_clause {
          fn encode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn #root::MemEncodable> {
              let collection: [&mut dyn #root::MemEncodable; #len_lit] = [
                #( #root::collections::to_encode_dyn_mut(#mut_refs) ),*
              ];
              collection.into_iter()
          }
        }

        impl #impl_generics #root::MemEncodable for #struct_name #ty_generics #where_clause {}
        impl #impl_generics #root::MemDecodable for #struct_name #ty_generics #where_clause {}
        impl #impl_generics #root::CollectionEncode for #struct_name #ty_generics #where_clause {}
        impl #impl_generics #root::CollectionDecode for #struct_name #ty_generics #where_clause {
          fn prepare_with_num_elements(&mut self, size: usize) -> Result<(), #root::MemDecodeError> {
              #root::collections::mem_decode_assert_num_elements(#len_lit, size)
          }

        }
    };

    Ok(output) // Return the generated code
}
