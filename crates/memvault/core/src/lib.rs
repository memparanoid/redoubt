// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memvault Core
//!
//! Core functionality for memvault.

#![cfg_attr(all(feature = "no_std", not(test)), no_std)]

mod cipherbox;
mod consts;
mod decrypt_decodable;
mod encrypt_encodable;
mod error;
mod master_key;

pub use cipherbox::CipherBox;
pub use master_key::leak_master_key;

#[cfg(test)]
mod tests;
