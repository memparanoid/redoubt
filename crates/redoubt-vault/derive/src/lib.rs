// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Procedural macros for redoubt-vault.
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
/// - `open` and `open_mut` over the whole struct
///
/// # Testing Utilities
///
/// By default, failure injection is gated with `#[cfg(test)]`, which means it's only
/// available when testing the crate where the cipherbox is defined.
///
/// To enable failure injection from dependent crates, use the `testing_feature` attribute:
///
/// ```ignore
/// #[cipherbox(SecretsBox, testing_feature = "test-utils")]
/// #[derive(RedoubtZero, RedoubtCodec)]
/// struct Secrets { ... }
/// ```
///
/// This changes the gate to `#[cfg(any(test, feature = "test-utils"))]`, allowing
/// dependent crates to enable the feature in their `Cargo.toml`:
///
/// ```toml
/// [dev-dependencies]
/// my-crate = { path = "...", features = ["test-utils"] }
/// ```
#[proc_macro_attribute]
pub fn cipherbox(attr: TokenStream, item: TokenStream) -> TokenStream {
    let (wrapper_name, custom_error, testing_feature) = parse_cipherbox_attr(attr);
    let input = parse_macro_input!(item as DeriveInput);
    expand(wrapper_name, custom_error, testing_feature, input)
        .unwrap_or_else(|e| e)
        .into()
}

// Extract custom error type and testing_feature from attribute tokens.
// Parses:
//   - "WrapperName"
//   - "WrapperName, error = ErrorType"
//   - "WrapperName, testing_feature = \"feature-name\""
// Returns (wrapper_name, custom_error_type, testing_feature)
fn parse_cipherbox_attr(attr: TokenStream) -> (Ident, Option<Type>, Option<String>) {
    parse_cipherbox_attr_inner(attr.to_string())
}

// Internal parsing function that takes a string for testability
pub(crate) fn parse_cipherbox_attr_inner(
    attr_str: String,
) -> (Ident, Option<Type>, Option<String>) {
    let parts: Vec<&str> = attr_str.split(',').map(|s| s.trim()).collect();

    let wrapper_name =
        syn::parse_str::<Ident>(parts[0]).expect("cipherbox: first argument must be wrapper name");

    let mut custom_error: Option<Type> = None;
    let mut testing_feature: Option<String> = None;

    // Parse remaining parts
    for part in &parts[1..] {
        if let Some(value) = part
            .strip_prefix("error")
            .and_then(|s| s.trim().strip_prefix('='))
        {
            let error_type_str = value.trim();
            custom_error = Some(
                syn::parse_str::<Type>(error_type_str).expect("cipherbox: invalid error type"),
            );
        } else if let Some(value) = part
            .strip_prefix("testing_feature")
            .and_then(|s| s.trim().strip_prefix('='))
        {
            let feature_str = value.trim().trim_matches('"');
            testing_feature = Some(feature_str.to_string());
        } else {
            panic!("cipherbox: unknown attribute parameter: {}", part);
        }
    }

    (wrapper_name, custom_error, testing_feature)
}
/// Find the root crate path from a list of candidates.
/// Candidates can be crate names like "redoubt-vault" or paths like "redoubt::vault".
pub(crate) fn find_root_with_candidates(candidates: &[&'static str]) -> TokenStream2 {
    for &candidate in candidates {
        // Check if candidate contains "::" (path syntax like "redoubt::vault")
        if let Some((crate_part, path_part)) = candidate.split_once("::") {
            match crate_name(crate_part) {
                Ok(FoundCrate::Itself) => {
                    // This shouldn't happen for "redoubt::*" but handle it
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
            // Regular crate name
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

    // The candidates that were looked for, and not a fixed sentence: this
    // resolves several crates, and a message naming one of them sends whoever
    // reads it to the wrong manifest line.
    let msg = format!(
        "cipherbox: none of {} is a dependency of this crate",
        candidates.join(", ")
    );
    let lit = LitStr::new(&msg, Span::call_site());
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
    let root = find_root_with_candidates(&["redoubt-zero-core", "redoubt-zero", "redoubt::zero"]);
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

    // Gated in the crate that writes the struct, not in this one: what reads
    // the sentinel is that crate's own tests, and a release build of it carries
    // an `Arc<AtomicBool>` per box for nothing.
    let sentinel_field: Field = syn::parse_quote! {
        #[cfg(test)]
        #[codec(default)]
        __sentinel: #root::ZeroizeOnDropSentinel
    };

    // Add to fields
    fields.named.push(sentinel_field);

    input
}

fn expand(
    wrapper_name: Ident,
    custom_error: Option<Type>,
    testing_feature: Option<String>,
    input: DeriveInput,
) -> Result<TokenStream2, TokenStream2> {
    // Inject __sentinel field if it doesn't exist
    let input = inject_zeroize_on_drop_sentinel(input);

    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let root =
        find_root_with_candidates(&["redoubt-vault-core", "redoubt-vault", "redoubt::vault"]);
    let redoubt_zero_root =
        find_root_with_candidates(&["redoubt-zero-core", "redoubt-zero", "redoubt::zero"]);
    let redoubt_aead_root = find_root_with_candidates(&["redoubt-aead", "redoubt::aead"]);

    // What the failure injection is gated on, where there is any. The error it
    // returns lives in `redoubt-vault-core` behind `test-utils`, and the
    // feature named here is the one switch that can carry both — so a box that
    // names none gets no injection emitted at all, rather than an attribute
    // that is always false.
    let test_cfg = testing_feature
        .as_ref()
        .map(|feature| quote! { #[cfg(feature = #feature)] });

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

    // Determine error type to use
    let error_type = custom_error
        .as_ref()
        .map(|ty| quote! { #ty })
        .unwrap_or_else(|| quote! { #root::CipherBoxError });

    // Generate failure mode enum name
    let failure_mode_enum_name = format_ident!("{}FailureMode", wrapper_name);

    // Generate failure mode enum (only with testing_feature)
    let failure_mode_enum = test_cfg.as_ref().map(|cfg| {
        quote! {
            #cfg
            #[derive(Debug, Clone, Copy)]
            pub enum #failure_mode_enum_name {
                None,
                FailOnNthOperation(usize),
            }
        }
    });

    let failure_counter_field = test_cfg.as_ref().map(|cfg| {
        quote! {
            /// Atomic so that the check below can sit in a method taking
            /// `&self`, which is what a read is.
            #cfg
            failure_counter: core::sync::atomic::AtomicUsize,
        }
    });

    let failure_counter_init = test_cfg.as_ref().map(|cfg| {
        quote! {
            #cfg
            failure_counter: core::sync::atomic::AtomicUsize::new(0),
        }
    });

    let set_failure_mode = test_cfg.as_ref().map(|cfg| {
        quote! {
            #cfg
            pub fn set_failure_mode(&self, mode: #failure_mode_enum_name) {
                use core::sync::atomic::Ordering;

                match mode {
                    #failure_mode_enum_name::None => {
                        self.failure_counter.store(0, Ordering::Relaxed);
                    }
                    #failure_mode_enum_name::FailOnNthOperation(n) => {
                        self.failure_counter.store(n, Ordering::Relaxed);
                    }
                }
            }
        }
    });

    // Helper to generate failure check code
    let failure_check = test_cfg.as_ref().map(|cfg| {
        quote! {
            #cfg
            {
                use core::sync::atomic::Ordering;

                let left = self.failure_counter.load(Ordering::Relaxed);

                if left > 0 {
                    self.failure_counter.store(left - 1, Ordering::Relaxed);

                    if left - 1 == 0 {
                        return Err(#root::CipherBoxError::IntentionalCipherBoxError.into());
                    }
                }
            }
        }
    });

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
            pub fn #leak_name(&self) -> Result<#redoubt_zero_root::ZeroizingGuard<#field_type>, #error_type> {
                #failure_check
                self.inner.leak_field::<#field_type, #idx_lit, #error_type>()
            }
        });

        open_methods.push(quote! {
            #[inline(always)]
            pub fn #open_name<F, R>(&self, f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
            where
                F: FnMut(&#field_type) -> Result<R, #error_type>,
                R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
            {
                #failure_check
                self.inner.open_field::<#field_type, #idx_lit, F, R, #error_type>(f)
            }
        });

        open_mut_methods.push(quote! {
            #[inline(always)]
            pub fn #open_mut_name<F, R>(&mut self, f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
            where
                F: FnMut(&mut #field_type) -> Result<R, #error_type>,
                R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
            {
                #failure_check
                self.inner.open_field_mut::<#field_type, #idx_lit, F, R, #error_type>(f)
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
        impl #root::EncryptStruct<#num_fields_lit> for #struct_name #ty_generics #where_clause {
            fn encrypt_into(
                &mut self,
                aead: &mut #redoubt_aead_root::Aead,
                aead_key: &[u8],
                nonces: &mut #root::Nonces<#num_fields_lit>,
                tags: &mut #root::Tags<#num_fields_lit>,
            ) -> Result<#root::Ciphertexts<#num_fields_lit>, #root::CipherBoxError> {
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
        impl #root::DecryptStruct<#num_fields_lit> for #struct_name #ty_generics #where_clause {
            fn decrypt_from(
                &mut self,
                aead: &#redoubt_aead_root::Aead,
                aead_key: &[u8],
                nonces: &#root::Nonces<#num_fields_lit>,
                tags: &#root::Tags<#num_fields_lit>,
                ciphertexts: &mut #root::Ciphertexts<#num_fields_lit>,
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

        // Generate failure mode enum (test-utils only)
        #failure_mode_enum

        // Generate wrapper struct
        #[derive(#redoubt_zero_root::RedoubtZero)]
        pub struct #wrapper_name {
            inner: #root::CipherBox<#struct_name, #num_fields_lit>,
            #failure_counter_field
        }

        impl #wrapper_name {
            #[inline(always)]
            pub fn new() -> Self {
                Self {
                    inner: #root::CipherBox::new(#redoubt_aead_root::Aead::default()),
                    #failure_counter_init
                }
            }

            #[inline(always)]
            pub fn open<F, R>(&self, f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
            where
                F: FnMut(&#struct_name) -> Result<R, #error_type>,
                R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
            {
                #failure_check
                self.inner.open(f)
            }

            #[inline(always)]
            pub fn open_mut<F, R>(&mut self, f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
            where
                F: FnMut(&mut #struct_name) -> Result<R, #error_type>,
                R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
            {
                #failure_check
                self.inner.open_mut(f)
            }

            #set_failure_mode

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
