// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Redoubt - Secure memory handling for Rust

#![cfg_attr(not(test), no_std)]

pub mod collections;
pub mod support;

pub use redoubt_aead::*;
pub use redoubt_codec::*;
pub use redoubt_vault::*;
pub use redoubt_zero::*;
