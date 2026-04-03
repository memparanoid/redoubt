// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Core traits and error types for HKDF-SHA256.
//!
//! Defines `HkdfApi`, the backend-agnostic trait implemented by Rust,
//! x86, and ARM backends.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

mod error;
mod traits;

pub use error::HkdfError;
pub use traits::HkdfApi;

#[cfg(test)]
mod tests {
    #[test]
    fn instrumentation() {
        let _ = crate::HkdfError::OutputTooLong;
    }
}
