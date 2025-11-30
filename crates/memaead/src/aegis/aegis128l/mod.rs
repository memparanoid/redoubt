// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L authenticated encryption.
//!
//! 128-bit key, 128-bit nonce, 8 x 128-bit state blocks.
//! Based on draft-irtf-cfrg-aegis-aead-18.

mod aead;
mod consts;
mod state;

pub use aead::Aegis128L;

#[cfg(test)]
mod tests;
