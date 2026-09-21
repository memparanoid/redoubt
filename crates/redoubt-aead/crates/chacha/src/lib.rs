// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ChaCha20 and the two things built on it.
//!
//! [`chacha20::ChaCha20`] is RFC 8439's stream cipher and Bernstein's original,
//! which differ only in where the nonce and the counter sit in the state.
//! [`hchacha20::HChaCha20`] is the same rounds used as a key derivation, and
//! [`xchacha20::XChaCha20`] is the two of them together: a nonce of twenty-four
//! bytes, long enough to pick at random rather than count.
//!
//! None of the three holds a key between calls.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

mod backend;
mod consts;

pub mod chacha20;
pub mod hchacha20;
pub mod xchacha20;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-utils"))]
pub use backend::HAS_ASM;
