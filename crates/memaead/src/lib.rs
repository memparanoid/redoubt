// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod aead;
mod chacha20;

pub use aead::{
    xchacha20poly1305_decrypt, xchacha20poly1305_encrypt, DecryptError, KEY_SIZE, NONCE_SIZE,
    TAG_SIZE,
};

#[cfg(test)]
pub(crate) mod tests;
