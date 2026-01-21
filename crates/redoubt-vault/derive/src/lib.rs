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

use heck::ToShoutySnakeCase;
use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Field, Fields, Ident, LitStr, Meta, Type, parse_macro_input,
};

enum StorageStrategy {
    Std,
    Portable,
}

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
    let (wrapper_name, custom_error, is_global, storage_strategy, testing_feature) =
        parse_cipherbox_attr(attr);
    let input = parse_macro_input!(item as DeriveInput);
    expand(
        wrapper_name,
        custom_error,
        is_global,
        storage_strategy,
        testing_feature,
        input,
    )
    .unwrap_or_else(|e| e)
    .into()
}

// Extract custom error type, global flag, storage strategy, and testing_feature from attribute tokens.
// Parses:
//   - "WrapperName"
//   - "WrapperName, error = ErrorType"
//   - "WrapperName, global = true"
//   - "WrapperName, testing_feature = \"feature-name\""
// Returns (wrapper_name, custom_error_type, is_global, storage_strategy, testing_feature)
fn parse_cipherbox_attr(
    attr: TokenStream,
) -> (
    Ident,
    Option<Type>,
    bool,
    Option<StorageStrategy>,
    Option<String>,
) {
    parse_cipherbox_attr_inner(attr.to_string())
}

// Internal parsing function that takes a string for testability
pub(crate) fn parse_cipherbox_attr_inner(
    attr_str: String,
) -> (
    Ident,
    Option<Type>,
    bool,
    Option<StorageStrategy>,
    Option<String>,
) {
    let parts: Vec<&str> = attr_str.split(',').map(|s| s.trim()).collect();

    let wrapper_name =
        syn::parse_str::<Ident>(parts[0]).expect("cipherbox: first argument must be wrapper name");

    let mut custom_error: Option<Type> = None;
    let mut is_global = false;
    let mut storage_strategy: Option<StorageStrategy> = None;
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
            .strip_prefix("global")
            .and_then(|s| s.trim().strip_prefix('='))
        {
            let global_str = value.trim();
            is_global = global_str == "true";
        } else if let Some(value) = part
            .strip_prefix("storage")
            .and_then(|s| s.trim().strip_prefix('='))
        {
            let storage_str = value.trim().trim_matches('"');
            storage_strategy = Some(if storage_str == "std" {
                StorageStrategy::Std
            } else {
                StorageStrategy::Portable
            });
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

    (
        wrapper_name,
        custom_error,
        is_global,
        storage_strategy,
        testing_feature,
    )
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
    let root = find_root_with_candidates(&["redoubt-zero-core", "redoubt-zero", "redoubt"]);
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

fn expand(
    wrapper_name: Ident,
    custom_error: Option<Type>,
    is_global: bool,
    storage_strategy: Option<StorageStrategy>,
    testing_feature: Option<String>,
    input: DeriveInput,
) -> Result<TokenStream2, TokenStream2> {
    // Inject __sentinel field if it doesn't exist
    let input = inject_zeroize_on_drop_sentinel(input);

    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let root = find_root_with_candidates(&["redoubt-vault-core", "redoubt-vault", "redoubt"]);
    let redoubt_zero_root =
        find_root_with_candidates(&["redoubt-zero-core", "redoubt-zero", "redoubt"]);
    let redoubt_aead_root = find_root_with_candidates(&["redoubt-aead", "redoubt"]);

    // Generate the test cfg attribute based on testing_feature
    let test_cfg = if let Some(ref feature) = testing_feature {
        quote! { #[cfg(any(test, feature = #feature))] }
    } else {
        quote! { #[cfg(test)] }
    };

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

    // Generate failure mode enum (test-only or with testing_feature)
    let failure_mode_enum = quote! {
        #test_cfg
        #[derive(Debug, Clone, Copy)]
        pub enum #failure_mode_enum_name {
            None,
            FailOnNthOperation(usize),
        }
    };

    // Helper to generate failure check code
    let failure_check = quote! {
        #test_cfg
        {
            if self.failure_counter > 0 {
                self.failure_counter -= 1;
                if self.failure_counter == 0 {
                    return Err(#root::CipherBoxError::IntentionalCipherBoxError.into());
                }
            }
        }
    };

    // Generate per-field methods
    let mut leak_methods = Vec::new();
    let mut open_methods = Vec::new();
    let mut open_mut_methods = Vec::new();

    // Vectors for global methods (populated in loop below if is_global)
    // IMPORTANT: These vectors contain code that MUST be injected inside `pub mod #global_module_name`
    // The generated code assumes it has access to module-local functions: lock(), release(), get_or_init()
    // These are only available within the global storage module context.
    let mut global_leak_methods = Vec::new();
    let mut global_open_methods = Vec::new();
    let mut global_open_mut_methods = Vec::new();

    // Determine storage strategy for global storage
    let use_portable_storage = if let Some(strategy) = storage_strategy {
        matches!(strategy, StorageStrategy::Portable)
    } else {
        !cfg!(feature = "std")
    };

    for (idx, (_, field)) in encryptable_fields.iter().enumerate() {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let idx_lit = syn::LitInt::new(&idx.to_string(), Span::call_site());

        let leak_name = format_ident!("leak_{}", field_name);
        let open_name = format_ident!("open_{}", field_name);
        let open_mut_name = format_ident!("open_{}_mut", field_name);

        leak_methods.push(quote! {
            #[inline(always)]
            pub fn #leak_name(&mut self) -> Result<#redoubt_zero_root::ZeroizingGuard<#field_type>, #error_type> {
                #failure_check
                self.inner.leak_field::<#field_type, #idx_lit, #error_type>()
            }
        });

        open_methods.push(quote! {
            #[inline(always)]
            pub fn #open_name<F, R>(&mut self, f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
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

        // Generate global methods if needed
        // Note: These methods reference the internal module which is generated later.
        // The internal module name follows the pattern: __{wrapper_name}_internal (lowercase)
        if is_global {
            let internal_module_name =
                format_ident!("__{}_internal", wrapper_name.to_string().to_shouty_snake_case().to_lowercase());

            if use_portable_storage {
                // Portable: Global leak method
                global_leak_methods.push(quote! {
                    pub fn #leak_name() -> Result<#redoubt_zero_root::ZeroizingGuard<#field_type>, #error_type> {
                        #internal_module_name::lock();
                        let _guard = #internal_module_name::PanicGuard;
                        let instance = #internal_module_name::get_or_init();
                        instance.#leak_name()
                    }
                });

                // Portable: Global open method
                global_open_methods.push(quote! {
                    pub fn #open_name<F, R>(f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
                    where
                        F: FnMut(&#field_type) -> Result<R, #error_type>,
                        R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
                    {
                        #internal_module_name::lock();
                        let _guard = #internal_module_name::PanicGuard;
                        let instance = #internal_module_name::get_or_init();
                        instance.#open_name(f)
                    }
                });

                // Portable: Global open_mut method
                global_open_mut_methods.push(quote! {
                    pub fn #open_mut_name<F, R>(f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
                    where
                        F: FnMut(&mut #field_type) -> Result<R, #error_type>,
                        R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
                    {
                        #internal_module_name::lock();
                        let _guard = #internal_module_name::PanicGuard;
                        let instance = #internal_module_name::get_or_init();
                        instance.#open_mut_name(f)
                    }
                });
            } else {
                // std: Global leak method
                global_leak_methods.push(quote! {
                    pub fn #leak_name() -> Result<#redoubt_zero_root::ZeroizingGuard<#field_type>, #error_type> {
                        let mutex = #internal_module_name::get_or_init();
                        let mut guard = mutex.lock().expect("Mutex poisoned");
                        guard.#leak_name()
                    }
                });

                // std: Global open method
                global_open_methods.push(quote! {
                    pub fn #open_name<F, R>(f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
                    where
                        F: FnMut(&#field_type) -> Result<R, #error_type>,
                        R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
                    {
                        let mutex = #internal_module_name::get_or_init();
                        let mut guard = mutex.lock().expect("Mutex poisoned");
                        guard.#open_name(f)
                    }
                });

                // std: Global open_mut method
                global_open_mut_methods.push(quote! {
                    pub fn #open_mut_name<F, R>(f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
                    where
                        F: FnMut(&mut #field_type) -> Result<R, #error_type>,
                        R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
                    {
                        let mutex = #internal_module_name::get_or_init();
                        let mut guard = mutex.lock().expect("Mutex poisoned");
                        guard.#open_mut_name(f)
                    }
                });
            }
        }
    }

    // Generate global storage code if needed (after loop so we can use global_*_methods)
    let global_storage_code = if is_global {
        let global_struct_name =
            format_ident!("{}", wrapper_name.to_string().to_shouty_snake_case());
        let internal_module_name =
            format_ident!("__{}_internal", wrapper_name.to_string().to_shouty_snake_case().to_lowercase());
        let static_name =
            format_ident!("STATIC_{}", wrapper_name.to_string().to_shouty_snake_case());

        if use_portable_storage {
            // Portable storage (no_std compatible)
            let init_static_name = format_ident!(
                "STATIC_{}_INIT",
                wrapper_name.to_string().to_shouty_snake_case()
            );
            let lock_static_name = format_ident!(
                "STATIC_{}_LOCK",
                wrapper_name.to_string().to_shouty_snake_case()
            );
            quote! {
                mod #internal_module_name {
                    use super::*;

                    // Wrapper to make UnsafeCell Sync
                    // SAFETY: Access is synchronized via spinlock
                    pub(super) struct SyncCell<T>(core::cell::UnsafeCell<T>);
                    unsafe impl<T> Sync for SyncCell<T> {}

                    impl<T> SyncCell<T> {
                        pub(super) const fn new(value: T) -> Self {
                            Self(core::cell::UnsafeCell::new(value))
                        }

                        pub(super) fn get(&self) -> *mut T {
                            self.0.get()
                        }
                    }

                    // Initialization states
                    pub(super) const STATE_UNINIT: u8 = 0;
                    pub(super) const STATE_IN_PROGRESS: u8 = 1;
                    pub(super) const STATE_DONE: u8 = 2;

                    pub(super) static #static_name: SyncCell<Option<#wrapper_name>> =
                        SyncCell::new(None);
                    pub(super) static #init_static_name: core::sync::atomic::AtomicU8 =
                        core::sync::atomic::AtomicU8::new(STATE_UNINIT);
                    pub(super) static #lock_static_name: core::sync::atomic::AtomicBool =
                        core::sync::atomic::AtomicBool::new(false);

                    #[cold]
                    #[inline(never)]
                    pub(super) fn init_slow() {
                        use core::sync::atomic::Ordering;

                        match #init_static_name.compare_exchange(
                            STATE_UNINIT,
                            STATE_IN_PROGRESS,
                            Ordering::Acquire,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => {
                                // We won the race, initialize
                                unsafe {
                                    let ptr = #static_name.get();
                                    *ptr = Some(#wrapper_name::new());
                                }

                                // Ensure write is visible before marking done
                                core::sync::atomic::fence(Ordering::Release);
                                #init_static_name.store(STATE_DONE, Ordering::Release);
                            }
                            Err(_) => {
                                // Another thread is initializing, spin until done
                                while #init_static_name.load(Ordering::Acquire) != STATE_DONE {
                                    core::hint::spin_loop();
                                }
                            }
                        }
                    }

                    pub(super) fn lock() {
                        use core::sync::atomic::Ordering;
                        while #lock_static_name.swap(true, Ordering::Acquire) {
                            core::hint::spin_loop();
                        }
                    }

                    pub(super) fn release() {
                        use core::sync::atomic::Ordering;
                        #lock_static_name.store(false, Ordering::Release);
                    }

                    pub(super) struct PanicGuard;

                    impl Drop for PanicGuard {
                        fn drop(&mut self) {
                            release();
                        }
                    }

                    pub(super) fn get_or_init() -> &'static mut #wrapper_name {
                        use core::sync::atomic::Ordering;

                        if #init_static_name.load(Ordering::Acquire) != STATE_DONE {
                            init_slow();
                        }

                        unsafe {
                            (*#static_name.get())
                                .as_mut()
                                .expect(concat!("Infallible: ", stringify!(#static_name), " has already been initialized"))
                        }
                    }
                }

                pub struct #global_struct_name;

                impl #global_struct_name {
                    pub fn open<F, R>(f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
                    where
                        F: FnMut(&#struct_name) -> Result<R, #error_type>,
                        R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
                    {
                        #internal_module_name::lock();
                        let _guard = #internal_module_name::PanicGuard;
                        let instance = #internal_module_name::get_or_init();
                        instance.open(f)
                    }

                    pub fn open_mut<F, R>(f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
                    where
                        F: FnMut(&mut #struct_name) -> Result<R, #error_type>,
                        R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
                    {
                        #internal_module_name::lock();
                        let _guard = #internal_module_name::PanicGuard;
                        let instance = #internal_module_name::get_or_init();
                        instance.open_mut(f)
                    }

                    #test_cfg
                    pub fn set_failure_mode(mode: #failure_mode_enum_name) {
                        #internal_module_name::lock();
                        let _guard = #internal_module_name::PanicGuard;
                        let instance = #internal_module_name::get_or_init();
                        instance.set_failure_mode(mode);
                    }

                    #( #global_leak_methods )*
                    #( #global_open_methods )*
                    #( #global_open_mut_methods )*
                }

                impl #redoubt_zero_root::StaticFastZeroizable for #global_struct_name {
                    fn fast_zeroize() {
                        use #redoubt_zero_root::FastZeroizable;
                        #internal_module_name::lock();
                        let _guard = #internal_module_name::PanicGuard;
                        let instance = #internal_module_name::get_or_init();
                        instance.fast_zeroize();
                    }
                }
            }
        } else {
            // std storage using OnceLock and Mutex
            quote! {
                mod #internal_module_name {
                    use super::*;

                    pub(super) static #static_name: std::sync::OnceLock<std::sync::Mutex<#wrapper_name>> =
                        std::sync::OnceLock::new();

                    pub(super) fn get_or_init() -> &'static std::sync::Mutex<#wrapper_name> {
                        #static_name.get_or_init(|| std::sync::Mutex::new(#wrapper_name::new()))
                    }
                }

                pub struct #global_struct_name;

                impl #global_struct_name {
                    pub fn open<F, R>(f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
                    where
                        F: FnMut(&#struct_name) -> Result<R, #error_type>,
                        R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
                    {
                        let mutex = #internal_module_name::get_or_init();
                        let mut guard = mutex.lock().expect("Mutex poisoned");
                        guard.open(f)
                    }

                    pub fn open_mut<F, R>(f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
                    where
                        F: FnMut(&mut #struct_name) -> Result<R, #error_type>,
                        R: Default + #redoubt_zero_root::FastZeroizable + #redoubt_zero_root::ZeroizationProbe,
                    {
                        let mutex = #internal_module_name::get_or_init();
                        let mut guard = mutex.lock().expect("Mutex poisoned");
                        guard.open_mut(f)
                    }

                    #test_cfg
                    pub fn set_failure_mode(mode: #failure_mode_enum_name) {
                        let mutex = #internal_module_name::get_or_init();
                        let mut guard = mutex.lock().expect("Mutex poisoned");
                        guard.set_failure_mode(mode);
                    }

                    #( #global_leak_methods )*
                    #( #global_open_methods )*
                    #( #global_open_mut_methods )*
                }

                impl #redoubt_zero_root::StaticFastZeroizable for #global_struct_name {
                    fn fast_zeroize() {
                        use #redoubt_zero_root::FastZeroizable;
                        let mutex = #internal_module_name::get_or_init();
                        let mut guard = mutex.lock().expect("Mutex poisoned");
                        guard.fast_zeroize();
                    }
                }
            }
        }
    } else {
        quote! {}
    };

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

        // Generate failure mode enum (test-utils only)
        #failure_mode_enum

        // Generate wrapper struct
        #[derive(#redoubt_zero_root::RedoubtZero)]
        pub struct #wrapper_name {
            inner: #root::CipherBox<#struct_name, #redoubt_aead_root::Aead, #num_fields_lit>,
            #test_cfg
            failure_counter: usize,
        }

        impl #wrapper_name {
            #[inline(always)]
            pub fn new() -> Self {
                Self {
                    inner: #root::CipherBox::new(#redoubt_aead_root::Aead::new()),
                    #test_cfg
                    failure_counter: 0,
                }
            }

            #[inline(always)]
            pub fn open<F, R>(&mut self, f: F) -> Result<#redoubt_zero_root::ZeroizingGuard<R>, #error_type>
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

            #test_cfg
            pub fn set_failure_mode(&mut self, mode: #failure_mode_enum_name) {
                match mode {
                    #failure_mode_enum_name::None => {
                        self.failure_counter = 0;
                    }
                    #failure_mode_enum_name::FailOnNthOperation(n) => {
                        self.failure_counter = n;
                    }
                }
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

        // Global storage code (if global = true)
        #global_storage_code
    };

    Ok(output)
}
