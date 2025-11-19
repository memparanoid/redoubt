// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

mod aead_buffer;
mod aead_key;
mod consts;
mod decrypt;
mod encrypt;
mod error;
mod guards;
mod xnonce;

pub use aead_buffer::{AeadBuffer, CapacityExceededError};
pub use aead_key::AeadKey;
pub use decrypt::decrypt_mem_decodable;
pub use encrypt::encrypt_mem_encodable;
pub use error::CryptoError;
pub use xnonce::XNonce;
