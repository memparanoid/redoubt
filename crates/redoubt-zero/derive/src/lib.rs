// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Procedural macros for the `redoubt_zero` crate.
//!
//! Provides the `#[derive(RedoubtZero)]` macro for automatic trait implementations.
//!
//! ## License
//!
//! GPL-3.0-only

#![warn(missing_docs)]

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
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Fields, Ident, Index, LitStr, Meta, Type, parse_macro_input,
};

/// Derives `FastZeroizable`, `ZeroizeMetadata`, `ZeroizationProbe`, and optionally `AssertZeroizeOnDrop` for a struct.
///
/// This macro automatically generates trait implementations for structs.
///
/// # Requirements
///
/// - All fields must implement `FastZeroizable` (except fields with `#[fast_zeroize(skip)]`)
///
/// # Optional Sentinel Field
///
/// - Named structs can include a field named `__sentinel: ZeroizeOnDropSentinel`
/// - Tuple structs can include a field of type `ZeroizeOnDropSentinel`
/// - If present, `AssertZeroizeOnDrop` will be implemented for testing drop behavior
///
/// # Attributes
///
/// - `#[fast_zeroize(drop)]`: Also generates a `Drop` implementation that calls `fast_zeroize()`
/// - `#[fast_zeroize(skip)]`: Skip a field from zeroization (e.g., immutable references)
///
/// # Generated Implementations
///
/// Always generated:
/// - `FastZeroizable`: Zeroizes all fields (except skipped)
/// - `ZeroizeMetadata`: Sets `CAN_BE_BULK_ZEROIZED = false`
/// - `ZeroizationProbe`: Checks if all fields are zeroized (except skipped and sentinel)
///
/// If `ZeroizeOnDropSentinel` field is present:
/// - `AssertZeroizeOnDrop`: Provides test helpers for verifying zeroization on drop
///
/// With `#[fast_zeroize(drop)]`:
/// - `Drop`: Calls `fast_zeroize()` on drop
///
/// # Examples
///
/// ## Without automatic Drop
///
/// ```rust
/// use redoubt_zero_derive::RedoubtZero;
/// use redoubt_zero_core::{ZeroizeOnDropSentinel, FastZeroizable};
///
/// #[derive(RedoubtZero)]
/// struct ApiKey {
///     key: Vec<u8>,
///     __sentinel: ZeroizeOnDropSentinel,
/// }
///
/// impl Drop for ApiKey {
///     fn drop(&mut self) {
///         self.fast_zeroize();
///     }
/// }
/// ```
///
/// ## With automatic Drop
///
/// ```rust
/// use redoubt_zero_derive::RedoubtZero;
/// use redoubt_zero_core::{ZeroizeOnDropSentinel, FastZeroizable};
///
/// #[derive(RedoubtZero)]
/// #[fast_zeroize(drop)]
/// struct ApiKey {
///     key: Vec<u8>,
///     __sentinel: ZeroizeOnDropSentinel,
/// }
/// // Drop is automatically generated
/// ```
#[proc_macro_derive(RedoubtZero, attributes(fast_zeroize))]
pub fn derive_redoubt_zero(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(input).unwrap_or_else(|e| e).into()
}

/// Finds the root crate path from a list of candidates.
///
/// Resolves the correct import path for `RedoubtZero` or `RedoubtZero-core` depending on context.
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

    let msg = "RedoubtZero: could not find redoubt-zero or redoubt-zero-core. Add redoubt-zero to Cargo.toml.";
    let lit = LitStr::new(msg, Span::call_site());
    quote! { compile_error!(#lit); }
}

/// Detects if a type is `ZeroizeOnDropSentinel` by checking the type path.
///
/// Used for tuple struct support where we identify the sentinel field by type.
pub(crate) fn is_zeroize_on_drop_sentinel_type(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Path(type_path)
        if type_path.path.segments.last()
            .map(|seg| seg.ident == "ZeroizeOnDropSentinel")
            .unwrap_or(false)
    )
}

/// Detects if a type is a mutable reference (&mut T).
///
/// For mutable references, we should pass `self.field` directly instead of `&mut self.field`
/// to avoid creating `&mut &mut T`.
pub(crate) fn is_mut_reference_type(ty: &Type) -> bool {
    if let Type::Reference(r) = ty {
        r.mutability.is_some()
    } else {
        false
    }
}

/// Detects if a type is an immutable reference (&T).
///
/// Immutable references cannot be zeroized since we don't have mutable access.
pub(crate) fn is_immut_reference_type(ty: &Type) -> bool {
    if let Type::Reference(r) = ty {
        r.mutability.is_none()
    } else {
        false
    }
}

/// Checks if a field has the `#[fast_zeroize(skip)]` attribute.
fn has_fast_zeroize_skip(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| match &attr.meta {
        Meta::List(meta_list) => {
            meta_list.path.is_ident("fast_zeroize") && meta_list.tokens.to_string().contains("skip")
        }
        _ => false,
    })
}

/// Checks if the struct has the `#[fast_zeroize(drop)]` attribute.
fn has_fast_zeroize_drop(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| match &attr.meta {
        Meta::List(meta_list) => {
            meta_list.path.is_ident("fast_zeroize") && meta_list.tokens.to_string().contains("drop")
        }
        _ => false,
    })
}

/// Sentinel field information.
struct SentinelState {
    index: usize,
    access: TokenStream2,
}

/// Expands the DeriveInput into the necessary implementation of `RedoubtZero`.
fn expand(input: DeriveInput) -> Result<TokenStream2, TokenStream2> {
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // 1) Resolve the `redoubt_zero_core` or `RedoubtZero` crate (prefer redoubt_zero_core)
    let root = find_root_with_candidates(&["redoubt-zero-core", "redoubt-zero", "redoubt"]);

    // 2) Get all fields as a Vec
    let all_fields: Vec<(usize, &syn::Field)> = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => named.named.iter().enumerate().collect(),
            Fields::Unnamed(unnamed) => unnamed.unnamed.iter().enumerate().collect(),
            Fields::Unit => vec![],
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "RedoubtZero can only be derived for structs (named or tuple).",
            )
            .to_compile_error());
        }
    };

    // 3) Identify the __sentinel field (optional)
    let sentinel_ident = format_ident!("__sentinel");
    let mut maybe_sentinel_state: Option<SentinelState> = None;

    for (i, f) in &all_fields {
        let is_sentinel = if let Some(ident) = &f.ident {
            // Named field: check if name is __sentinel
            if *ident == sentinel_ident {
                maybe_sentinel_state = Some(SentinelState {
                    index: *i,
                    access: quote! { self.#sentinel_ident },
                });
                true
            } else {
                false
            }
        } else {
            // Unnamed field: check if type is ZeroizeOnDropSentinel
            if is_zeroize_on_drop_sentinel_type(&f.ty) {
                let idx = Index::from(*i);
                maybe_sentinel_state = Some(SentinelState {
                    index: *i,
                    access: quote! { self.#idx },
                });
                true
            } else {
                false
            }
        };

        if is_sentinel {
            break;
        }
    }

    // 4) Validate and filter fields
    // - Check for immutable references without #[fast_zeroize(skip)]
    // - Filter out fields with #[fast_zeroize(skip)]
    // - Filter out sentinel (if present)
    let sentinel_idx = maybe_sentinel_state.as_ref().map(|s| s.index);

    for (i, f) in &all_fields {
        if Some(*i) == sentinel_idx {
            continue;
        }

        if is_immut_reference_type(&f.ty) && !has_fast_zeroize_skip(&f.attrs) {
            let field_name = if let Some(ident) = &f.ident {
                format!("field `{}`", ident)
            } else {
                format!("field at index {}", i)
            };

            return Err(syn::Error::new_spanned(
                &f.ty,
                format!(
                    "{} has type `&T` (immutable reference) which cannot be zeroized. \
                     Add `#[fast_zeroize(skip)]` to exclude it from zeroization.",
                    field_name
                ),
            )
            .to_compile_error());
        }
    }

    // 5) Generate two sets of field references:
    //    - immut_refs_without_sentinel: for ZeroizationProbe (excludes sentinel and skipped)
    //    - mut_refs_with_sentinel: for FastZeroizable (includes sentinel, excludes skipped)

    // For ZeroizationProbe: filter out sentinel and skipped fields
    // Special handling: if field is already &mut T, pass self.field directly (not &self.field)
    let (immut_refs_without_sentinel, _): (Vec<TokenStream2>, Vec<TokenStream2>) = all_fields
        .iter()
        .filter(|(i, f)| Some(*i) != sentinel_idx && !has_fast_zeroize_skip(&f.attrs))
        .map(|(i, f)| {
            let is_mut_ref = is_mut_reference_type(&f.ty);

            if let Some(ident) = &f.ident {
                let immut_ref = if is_mut_ref {
                    quote! { self.#ident }
                } else {
                    quote! { &self.#ident }
                };
                (immut_ref, quote! { &mut self.#ident })
            } else {
                let idx = Index::from(*i);
                let immut_ref = if is_mut_ref {
                    quote! { self.#idx }
                } else {
                    quote! { &self.#idx }
                };
                (immut_ref, quote! { &mut self.#idx })
            }
        })
        .unzip();

    // For FastZeroizable: include ALL fields except skipped (including sentinel)
    // Special handling: if field is already &mut T, pass self.field directly (not &mut self.field)
    let (_, mut_refs_with_sentinel): (Vec<TokenStream2>, Vec<TokenStream2>) = all_fields
        .iter()
        .filter(|(_, f)| !has_fast_zeroize_skip(&f.attrs))
        .map(|(i, f)| {
            let is_mut_ref = is_mut_reference_type(&f.ty);

            if let Some(ident) = &f.ident {
                let mut_ref = if is_mut_ref {
                    quote! { self.#ident }
                } else {
                    quote! { &mut self.#ident }
                };
                (quote! { &self.#ident }, mut_ref)
            } else {
                let idx = Index::from(*i);
                let mut_ref = if is_mut_ref {
                    quote! { self.#idx }
                } else {
                    quote! { &mut self.#idx }
                };
                (quote! { &self.#idx }, mut_ref)
            }
        })
        .unzip();

    // 5) Calculate lengths
    let len_without_sentinel = immut_refs_without_sentinel.len();
    let len_without_sentinel_lit =
        syn::LitInt::new(&len_without_sentinel.to_string(), Span::call_site());

    let len_with_sentinel = mut_refs_with_sentinel.len();
    let len_with_sentinel_lit = syn::LitInt::new(&len_with_sentinel.to_string(), Span::call_site());

    // 6) Check if we should generate Drop implementation
    let should_generate_drop = has_fast_zeroize_drop(&input.attrs);

    // 7) Emit the trait implementations
    let drop_impl = if should_generate_drop {
        quote! {
            impl #impl_generics Drop for #struct_name #ty_generics #where_clause {
                fn drop(&mut self) {
                    #root::FastZeroizable::fast_zeroize(self);
                }
            }
        }
    } else {
        quote! {}
    };

    let output = quote! {
        impl #impl_generics #root::ZeroizeMetadata for #struct_name #ty_generics #where_clause {
            const CAN_BE_BULK_ZEROIZED: bool = false;
        }

        impl #impl_generics #root::FastZeroizable for #struct_name #ty_generics #where_clause {
            fn fast_zeroize(&mut self) {
                let fields: [&mut dyn #root::FastZeroizable; #len_with_sentinel_lit] = [
                    #( #root::collections::to_fast_zeroizable_dyn_mut(#mut_refs_with_sentinel) ),*
                ];
                #root::collections::zeroize_collection(&mut fields.into_iter())
            }
        }

        impl #impl_generics #root::ZeroizationProbe for #struct_name #ty_generics #where_clause {
            fn is_zeroized(&self) -> bool {
                let fields: [&dyn #root::ZeroizationProbe; #len_without_sentinel_lit] = [
                    #( #root::collections::to_zeroization_probe_dyn_ref(#immut_refs_without_sentinel) ),*
                ];
                #root::collections::collection_zeroed(&mut fields.into_iter())
            }
        }

        #drop_impl
    };

    // Conditionally implement AssertZeroizeOnDrop if sentinel is present
    let assert_impl = if let Some(sentinel_state) = maybe_sentinel_state {
        let sentinel_access = sentinel_state.access;
        quote! {
            impl #impl_generics #root::AssertZeroizeOnDrop for #struct_name #ty_generics #where_clause {
                fn clone_sentinel(&self) -> #root::ZeroizeOnDropSentinel {
                    #sentinel_access.clone()
                }

                fn assert_zeroize_on_drop(self) {
                    #root::assert::assert_zeroize_on_drop(self);
                }
            }
        }
    } else {
        quote! {}
    };

    let full_output = quote! {
        #output
        #assert_impl
    };

    Ok(full_output)
}
