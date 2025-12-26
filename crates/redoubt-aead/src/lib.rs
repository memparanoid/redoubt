// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

mod aead;
#[cfg(all(feature = "asm", is_aegis_asm_eligible))]
mod aegis_asm;
mod error;
mod feature_detector;
mod traits;
mod xchacha20poly1305;

pub mod support;

pub use aead::Aead;
pub use error::AeadError;
pub use traits::{AeadApi, AeadBackend};

#[cfg(feature = "test_utils")]
pub use support::test_utils;
