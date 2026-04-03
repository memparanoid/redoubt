// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Pure Rust HKDF-SHA256 implementation.
//!
//! Provides `RustBackend` implementing `HkdfApi` from `redoubt-hkdf-core`.
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

mod hkdf;
mod hmac;
mod sha256;
mod word32;

pub use backend::RustBackend;
