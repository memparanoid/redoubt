// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub mod xchacha20poly1305;

mod error;
mod traits;

pub use error::DecryptError;
pub use traits::Aead;
