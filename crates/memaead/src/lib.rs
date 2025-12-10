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
pub use traits::AeadApi;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "wasi")
))]
pub mod aegis;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "wasi")
))]
pub use aegis::Aegis128L;
