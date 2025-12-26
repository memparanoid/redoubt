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
mod support;
mod traits;
mod xchacha20poly1305;

pub use aead::Aead;
pub use error::AeadError;
pub use traits::{AeadApi, AeadBackend};
