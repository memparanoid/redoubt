// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The contract every AEAD here answers to, the widths they work in, the one
//! error they fail with, and the one value they may branch on after a secret.
//!
//! It allocates nothing and takes no dependency but the one that writes its
//! error messages, so a backend implements these traits without inheriting
//! anybody's idea of where randomness comes from.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

mod declassify;
mod error;
mod traits;

pub mod consts;

pub use declassify::declassify;
pub use error::AeadCoreError;
pub use traits::{AeadBackend, AeadDecrypt, AeadEncrypt, AeadSizes};
