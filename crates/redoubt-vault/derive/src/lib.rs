// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Procedural macros for redoubt-vault.

#[cfg(test)]
mod tests;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Field, Fields, Ident, LitStr, Meta, Type, parse_macro_input,
};

/// Derives a CipherBox wrapper struct with per-field access methods.
///
/// **IMPORTANT**: This attribute macro MUST appear BEFORE `#[derive(RedoubtZero)]` to work correctly.
/// It automatically injects the `__sentinel` field that RedoubtZero requires.
///
/// # Usage
///
/// ```ignore
/// #[cipherbox(WalletSecretsCipherBox)]  // ← Must come FIRST
/// #[derive(RedoubtZero, RedoubtCodec)]              // ← Then derives
/// #[fast_zeroize(drop)]
/// struct WalletSecrets {
///     master_seed: [u8; 32],
///     encryption_key: [u8; 32],
///     // __sentinel is auto-injected, no need to add it manually!
/// }
/// ```
///
/// # Attribute Macro Ordering
///
/// Attribute macros execute in order from top to bottom, BEFORE derive macros.
/// Since `#[derive(RedoubtZero)]` requires a `__sentinel` field, and `#[cipherbox]`
/// injects it automatically, `#[cipherbox]` must appear above `#[derive(RedoubtZero)]`.
///
/// ✅ Correct order:
/// ```ignore
/// #[cipherbox(MyBox)]
/// #[derive(RedoubtZero, RedoubtCodec)]
/// struct MySecrets { ... }
/// ```
///
/// 🚫 Incorrect order (will fail to compile):
/// ```ignore
/// #[derive(RedoubtZero, RedoubtCodec)]  // ← Runs first, fails because __sentinel is missing
/// #[cipherbox(MyBox)]       // ← Runs second, but too late
/// struct MySecrets { ... }
/// ```
///
/// # Generated Code
///
/// This generates:
/// - `WalletSecretsCipherBox` wrapper struct
/// - `EncryptStruct<N>` and `DecryptStruct<N>` trait impls
/// - Per-field `leak_*`, `open_*`, `open_*_mut` methods
/// - Global `open` and `open_mut` methods
#[proc_macro_attribute]
pub fn cipherbox(attr: TokenStream, item: TokenStream) -> TokenStream {
    let wrapper_name = parse_macro_input!(attr as Ident);
    let input = parse_macro_input!(item as DeriveInput);
    expand(wrapper_name, input).unwrap_or_else(|e| e).into()
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

    let msg = "cipherbox: could not find redoubt-vault or redoubt-vault-core. Add redoubt-vault to Cargo.toml.";
    let lit = LitStr::new(msg, Span::call_site());
    quote! { compile_error!(#lit); }
}

/// Detects if a type is `ZeroizeOnDropSentinel` by checking the type path.
fn is_zeroize_on_drop_sentinel_type(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Path(type_path)
        if type_path.path.segments.last()
            .map(|seg| seg.ident == "ZeroizeOnDropSentinel")
            .unwrap_or(false)
    )
}

/// Checks if a field has the `#[codec(default)]` attribute.
fn has_codec_default(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        matches!(&attr.meta, Meta::List(meta_list)
            if meta_list.path.is_ident("codec")
            && meta_list.tokens.to_string().contains("default"))
    })
}

/// Injects `__sentinel: ZeroizeOnDropSentinel` field with `#[codec(default)]` attribute.
fn inject_zeroize_on_drop_sentinel(mut input: DeriveInput) -> DeriveInput {
    let root = find_root_with_candidates(&["redoubt-zero-core", "redoubt-zero"]);
    let data = match &mut input.data {
        Data::Struct(data) => data,
        _ => {
            // Not a struct - just return as-is and let later validation handle it
            return input;
        }
    };

    let fields = match &mut data.fields {
        Fields::Named(fields) => fields,
        // Unnamed and Unit structs - just return as-is, no injection needed
        Fields::Unnamed(_) | Fields::Unit => {
            return input;
        }
    };

    // Check if __sentinel already exists
    let has_sentinel = fields
        .named
        .iter()
        .any(|f| f.ident.as_ref().map(|i| i == "__sentinel").unwrap_or(false));

    if has_sentinel {
        // Already has __sentinel, don't inject
        return input;
    }

    // Create the __sentinel field
    let sentinel_field: Field = syn::parse_quote! {
        #[codec(default)]
        __sentinel: #root::ZeroizeOnDropSentinel
    };

    // Add to fields
    fields.named.push(sentinel_field);

    input
}

fn expand(wrapper_name: Ident, input: DeriveInput) -> Result<TokenStream2, TokenStream2> {
    // Inject __sentinel field if it doesn't exist
    let input = inject_zeroize_on_drop_sentinel(input);

    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let root = find_root_with_candidates(&["redoubt-vault-core", "redoubt-vault"]);
    let redoubt_zero_root = find_root_with_candidates(&["redoubt-zero-core", "redoubt-zero"]);
    let redoubt_aead_root = find_root_with_candidates(&["redoubt-aead"]);

    // Get fields
    let fields: Vec<(usize, &syn::Field)> = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => named.named.iter().enumerate().collect(),
            Fields::Unnamed(_) => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "cipherbox only supports named structs.",
                )
                .to_compile_error());
            }
            Fields::Unit => vec![],
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "cipherbox can only be derived for structs.",
            )
            .to_compile_error());
        }
    };

    // Filter out fields with #[codec(default)] or ZeroizeOnDropSentinel type
    let encryptable_fields: Vec<(usize, &syn::Field)> = fields
        .iter()
        .filter(|(_, f)| !has_codec_default(&f.attrs) && !is_zeroize_on_drop_sentinel_type(&f.ty))
        .map(|(i, f)| (*i, *f))
        .collect();

    let num_fields = encryptable_fields.len();
    let num_fields_lit = syn::LitInt::new(&num_fields.to_string(), Span::call_site());

    // Generate field references
    let mut_refs: Vec<TokenStream2> = encryptable_fields
        .iter()
        .map(|(_, f)| {
            let ident = f.ident.as_ref().unwrap();
            quote! { &mut self.#ident }
        })
        .collect();

    // Generate per-field methods
    let mut leak_methods = Vec::new();
    let mut open_methods = Vec::new();
    let mut open_mut_methods = Vec::new();

    for (idx, (_, field)) in encryptable_fields.iter().enumerate() {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let idx_lit = syn::LitInt::new(&idx.to_string(), Span::call_site());

        let leak_name = format_ident!("leak_{}", field_name);
        let open_name = format_ident!("open_{}", field_name);
        let open_mut_name = format_ident!("open_{}_mut", field_name);

        leak_methods.push(quote! {
            #[inline(always)]
            pub fn #leak_name(&mut self) -> Result<#redoubt_zero_root::ZeroizingGuard<#field_type>, #root::CipherBoxError> {
                self.inner.leak_field::<#field_type, #idx_lit>()
            }
        });

        open_methods.push(quote! {
            #[inline(always)]
            pub fn #open_name<F>(&mut self, f: F) -> Result<(), #root::CipherBoxError>
            where
                F: Fn(&#field_type),
            {
                self.inner.open_field::<#field_type, #idx_lit, F>(f)
            }
        });

        open_mut_methods.push(quote! {
            #[inline(always)]
            pub fn #open_mut_name<F>(&mut self, f: F) -> Result<(), #root::CipherBoxError>
            where
                F: Fn(&mut #field_type),
            {
                self.inner.open_field_mut::<#field_type, #idx_lit, F>(f)
            }
        });
    }

    let output = quote! {
        // Re-emit the original struct
        #input

        // Import trait so methods are in scope
        use #root::CipherBoxDyns as _;

        // Implement CipherBoxDyns
        impl #impl_generics #root::CipherBoxDyns<#num_fields_lit> for #struct_name #ty_generics #where_clause {
            fn to_encryptable_dyn_fields(&mut self) -> [&mut dyn #root::Encryptable; #num_fields_lit] {
                [
                    #( #mut_refs ),*
                ]
            }

            fn to_decryptable_dyn_fields(&mut self) -> [&mut dyn #root::Decryptable; #num_fields_lit] {
                [
                    #( #mut_refs ),*
                ]
            }
        }

        // Implement EncryptStruct
        impl<A: #redoubt_aead_root::AeadApi> #root::EncryptStruct<A, #num_fields_lit> for #struct_name #ty_generics #where_clause {
            fn encrypt_into(
                &mut self,
                aead: &mut A,
                aead_key: &[u8],
                nonces: &mut [Vec<u8>; #num_fields_lit],
                tags: &mut [Vec<u8>; #num_fields_lit],
            ) -> Result<[Vec<u8>; #num_fields_lit], #root::CipherBoxError> {
                #root::encrypt_into(
                    self.to_encryptable_dyn_fields(),
                    aead,
                    aead_key,
                    nonces,
                    tags,
                )
            }
        }

        // Implement DecryptStruct
        impl<A: #redoubt_aead_root::AeadApi> #root::DecryptStruct<A, #num_fields_lit> for #struct_name #ty_generics #where_clause {
            fn decrypt_from(
                &mut self,
                aead: &mut A,
                aead_key: &[u8],
                nonces: &mut [Vec<u8>; #num_fields_lit],
                tags: &mut [Vec<u8>; #num_fields_lit],
                ciphertexts: &mut [Vec<u8>; #num_fields_lit],
            ) -> Result<(), #root::CipherBoxError> {
                #root::decrypt_from(
                    &mut self.to_decryptable_dyn_fields(),
                    aead,
                    aead_key,
                    nonces,
                    tags,
                    ciphertexts,
                )
            }
        }

        // Generate wrapper struct
        pub struct #wrapper_name {
            inner: #root::CipherBox<#struct_name, #redoubt_aead_root::Aead, #num_fields_lit>,
        }

        impl #wrapper_name {
            #[inline(always)]
            pub fn new() -> Self {
                Self {
                    inner: #root::CipherBox::new(#redoubt_aead_root::Aead::new()),
                }
            }

            #[inline(always)]
            pub fn open<F>(&mut self, f: F) -> Result<(), #root::CipherBoxError>
            where
                F: Fn(&#struct_name),
            {
                self.inner.open(f)
            }

            #[inline(always)]
            pub fn open_mut<F>(&mut self, f: F) -> Result<(), #root::CipherBoxError>
            where
                F: Fn(&mut #struct_name),
            {
                self.inner.open_mut(f)
            }

            #( #leak_methods )*

            #( #open_methods )*

            #( #open_mut_methods )*
        }

        impl Default for #wrapper_name {
            fn default() -> Self {
                Self::new()
            }
        }
    };

    Ok(output)
}
