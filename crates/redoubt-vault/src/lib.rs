// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Redoubt Vault
//!
//! Proxy crate that re-exports redoubt-vault-core and redoubt-vault-derive.

#![cfg_attr(all(feature = "no_std", not(test)), no_std)]

pub use redoubt_vault_core::*;
pub use redoubt_vault_derive::*;
