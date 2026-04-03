// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Core traits and error types for AEAD backends.
//!
//! Defines `AeadBackend` (type-safe) and `AeadApi` (object-safe) traits
//! implemented by XChaCha20-Poly1305 and AEGIS-128L backends.
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

mod error;
mod traits;

pub use error::AeadError;
pub use redoubt_rand::EntropyError;
pub use traits::{AeadApi, AeadBackend};
