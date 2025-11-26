// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod aead;
mod chacha20;
mod consts;
mod poly1305;
mod types;

pub use aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt, DecryptError};
pub use consts::{KEY_SIZE, TAG_SIZE, XNONCE_SIZE};
pub use types::{AeadKey, XNonce};

#[cfg(test)]
pub(crate) mod tests;
