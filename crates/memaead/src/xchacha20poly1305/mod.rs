// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

mod aead;
mod chacha20;
mod consts;
mod error;
mod poly1305;
mod types;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod asm;

pub use aead::XChacha20Poly1305;
pub use consts::{KEY_SIZE, TAG_SIZE, XNONCE_SIZE};
pub use error::DecryptError;
pub use types::{AeadKey, XNonce};
