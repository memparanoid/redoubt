// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

mod consts;
mod decrypt;
mod encrypt;
mod error;
mod guards;

pub use decrypt::decrypt_decodable;
pub use encrypt::encrypt_encodable;
pub use error::CryptoError;
