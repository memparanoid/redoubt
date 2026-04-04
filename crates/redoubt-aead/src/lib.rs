// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L and XChaCha20-Poly1305 AEAD with automatic backend selection.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
mod tests;

mod aead;
mod feature_detector;

/// Support module including test utilities.
pub mod support;

pub use aead::{Aead, AeadVariant};
pub use redoubt_aead_core::{AeadApi, AeadBackend, AeadError};
pub use redoubt_aead_xchacha::{
    CHACHA20_BERNSTEIN_NONCE_SIZE, CHACHA20_NONCE_SIZE, ChaCha20, HChaCha20, Poly1305, XChaCha20,
};

#[cfg(feature = "test-utils")]
pub use support::test_utils;
