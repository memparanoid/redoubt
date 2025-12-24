// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

pub mod support;
pub mod xchacha20poly1305;

mod aead;
mod error;
mod feature_detector;
mod traits;

pub use aead::Aead;
pub use error::AeadError;
pub use traits::{AeadApi, AeadBackend};

#[cfg(is_aegis_asm_eligible)]
pub mod aegis_asm;

#[cfg(is_aegis_asm_eligible)]
pub use aegis_asm::Aegis128L;
