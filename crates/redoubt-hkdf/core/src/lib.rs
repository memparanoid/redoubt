// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Core traits, error types, pure Rust implementation, and test infrastructure
//! for HKDF-SHA256.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
mod tests;

mod backend;
mod error;
mod traits;

// Internal Rust implementation modules
mod hkdf;
mod hmac;
mod sha256;
mod word32;

/// Support module including test utilities.
#[cfg(any(test, feature = "test-utils"))]
pub mod support;

pub use backend::RustBackend;
pub use error::HkdfError;
pub use traits::HkdfApi;
