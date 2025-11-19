// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memzer-derive
//!
//! Derive macros for memzer protected memory.
//!
//! This crate provides procedural macros for automatically implementing
//! zeroization and protected memory traits.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

/// Derive macro for ProtectedMemory trait
#[proc_macro_derive(ProtectedMemory)]
pub fn derive_protected_memory(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let expanded = quote! {
        impl memzer_core::Zeroize for #name {
            fn zeroize(&mut self) {
                // Implementation will zero all fields
                todo!("Implementation pending")
            }
        }

        impl Drop for #name {
            fn drop(&mut self) {
                use memzer_core::Zeroize;
                self.zeroize();
            }
        }
    };

    TokenStream::from(expanded)
}
