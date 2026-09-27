// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Redoubt Vault Core
//!
//! Core functionality for redoubt-vault.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests;

mod cipherbox;
mod consts;
mod error;
mod helpers;
mod master_key;
mod traits;
mod types;
mod utils;
mod workspace;

#[cfg(any(test, feature = "test-utils"))]
pub use master_key::derive_next_cipherbox_key;

pub use cipherbox::CipherBox;
pub use error::CipherBoxError;
pub use helpers::{decrypt_from, encrypt_into};
pub use traits::{CipherBoxDyns, DecryptStruct, Decryptable, EncryptStruct, Encryptable};
pub use types::{Ciphertext, Ciphertexts, Data, DataBuffers, Nonce, Nonces, Tag, Tags};
