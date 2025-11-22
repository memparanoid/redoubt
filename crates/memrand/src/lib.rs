// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memrand
//!
//! Cryptographically secure random number generation for the Memora framework.
//!
//! Provides entropy sources and nonce generators for cryptographic operations,
//! specifically designed for XChaCha20-Poly1305 AEAD encryption.
//!
//! ## Core Types
//!
//! - [`SystemEntropySource`]: OS-level CSPRNG (via `getrandom`)
//! - [`XNonceSessionGenerator`]: Session-based 192-bit nonce generator
//!
//! ## Traits
//!
//! - [`EntropySource`]: Interface for CSPRNGs
//! - [`XNonceGenerator`]: Interface for XChaCha20 nonce generation
//!
//! ## Example
//!
//! ```rust
//! use memrand::{SystemEntropySource, XNonceSessionGenerator, XNonceGenerator, EntropySource};
//!
//! // Create entropy source
//! let entropy = SystemEntropySource {};
//!
//! // Generate random bytes
//! let mut key = [0u8; 32];
//! entropy.fill_bytes(&mut key).expect("Failed to generate entropy");
//!
//! // Create nonce generator
//! let mut nonce_gen = XNonceSessionGenerator::new(&entropy);
//! let mut nonce = [0u8; 24];
//! nonce_gen.fill_current_xnonce(&mut nonce).expect("Failed to generate nonce");
//! ```
//!
//! ## Integration with Memora
//!
//! `memrand` is used throughout the Memora stack:
//! - **memcrypt**: Key and nonce generation for AEAD encryption
//! - **memvault**: Entropy for master key derivation
//!
//! ## Platform Support
//!
//! Supports all platforms via `getrandom`:
//! - Linux/Android: `getrandom()` syscall
//! - macOS/iOS: `getentropy()`
//! - Windows: `BCryptGenRandom`
//! - WASI: `random_get`

#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
mod tests;

mod error;
mod session;
mod support;
mod system;
mod traits;

pub use error::EntropyError;
pub use session::XNonceSessionGenerator;
pub use system::SystemEntropySource;
pub use traits::{EntropySource, XNonceGenerator};

#[cfg(any(test, feature = "test_utils"))]
pub use support::test_utils;
