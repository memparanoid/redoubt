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

#[cfg(test)]
mod tests;

mod aead;
mod feature_detector;

/// Support module including test utilities.
pub mod support;

pub use aead::Aead;
pub use redoubt_aead_core::{AeadApi, AeadBackend, AeadError};

#[cfg(feature = "test-utils")]
pub use support::test_utils;
