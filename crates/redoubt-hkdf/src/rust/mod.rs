// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Pure Rust implementations (SHA-256 based)

#[cfg(test)]
mod tests;

pub(crate) mod hkdf;
pub(crate) mod hmac;
pub(crate) mod sha256;
pub(crate) mod word32;
