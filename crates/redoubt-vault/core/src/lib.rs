// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Redoubt Vault Core
//!
//! Core functionality for redoubt-vault.

#![cfg_attr(all(feature = "no_std", not(test)), no_std)]

extern crate alloc;

mod cipherbox;
mod consts;
mod error;
mod helpers;
mod master_key;
mod traits;

pub use cipherbox::CipherBox;
pub use error::CipherBoxError;
pub use helpers::{decrypt_from, encrypt_into};
pub use master_key::leak_master_key;
pub use traits::{CipherBoxDyns, DecryptStruct, Decryptable, EncryptStruct, Encryptable};

#[cfg(feature = "__internal__forensics")]
pub use master_key::storage::reset as reset_master_key;

#[cfg(test)]
mod tests;
