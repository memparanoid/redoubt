// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The contract every AEAD here answers to, the widths they work in, and the
//! one error they fail with.
//!
//! Nothing sits below this crate. It implements no algorithm, allocates
//! nothing and takes no dependency but the one that writes its error messages,
//! so a backend implements these traits without inheriting anybody's idea of
//! where randomness comes from.
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

mod backend;
mod error;
mod traits;

pub mod consts;

pub use backend::Backend;
pub use error::AeadError;
pub use traits::{AeadBackend, AeadDecrypt, AeadEncrypt, AeadSizes};
