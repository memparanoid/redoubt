// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

pub mod xchacha20poly1305;

mod aead;
mod error;
mod traits;

pub use aead::Aead;
pub use error::DecryptError;
pub(crate) use traits::AeadBackend;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod aegis;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub use aegis::Aegis128L;
