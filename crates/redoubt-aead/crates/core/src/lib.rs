// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The contract every AEAD here answers to, the widths they work in, the one
//! error they fail with, and the comparison every one of them ends on.
//!
//! Nothing sits below this crate. It allocates nothing and takes no dependency
//! but the one that writes its error messages, so a backend implements these
//! traits without inheriting anybody's idea of where randomness comes from.
//!
//! The one thing here that is code rather than contract is
//! [`constant_time_eq`]. Every construction above finishes by holding a tag it
//! computed against one that arrived, and written once per construction it
//! would be two folds that agree today. What it is doing in assembly, and why
//! the portable one cannot make the same promise, is in `backend`.
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

mod backend;
mod error;
mod traits;

pub mod consts;

pub use backend::constant_time_eq;
pub use error::AeadCoreError;
pub use traits::{AeadBackend, AeadDecrypt, AeadEncrypt, AeadSizes};
