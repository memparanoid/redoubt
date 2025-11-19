// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memcode-derive
//!
//! Derive macros for memcode serialization.
//!
//! This crate provides procedural macros for automatically implementing
//! memcode serialization traits.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Derive macro for Encode trait
#[proc_macro_derive(Encode)]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let expanded = quote! {
        impl memcode_core::Encode for #name {
            fn encode(&self, _buf: &mut [u8]) -> Result<usize, memcode_core::Error> {
                todo!("Implementation pending")
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derive macro for Decode trait
#[proc_macro_derive(Decode)]
pub fn derive_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let expanded = quote! {
        impl memcode_core::Decode for #name {
            fn decode(_buf: &[u8]) -> Result<Self, memcode_core::Error> {
                todo!("Implementation pending")
            }
        }
    };

    TokenStream::from(expanded)
}
