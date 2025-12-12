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
//! - [`NonceSessionGenerator`]: Session-based nonce generator with configurable size
//!
//! ## Traits
//!
//! - [`EntropySource`]: Interface for CSPRNGs
//! - [`NonceGenerator`]: Interface for nonce generation
//!
//! ## Example
//!
//! ```rust
//! use memrand::{SystemEntropySource, NonceSessionGenerator, NonceGenerator, EntropySource};
//!
//! // Create entropy source
//! let entropy = SystemEntropySource {};
//!
//! // Generate random bytes
//! let mut key = [0u8; 32];
//! entropy.fill_bytes(&mut key).expect("Failed to generate entropy");
//!
//! // Create nonce generator
//! let mut nonce_gen = NonceSessionGenerator::<SystemEntropySource, 24>::new(SystemEntropySource {});
//! let nonce = nonce_gen.generate_nonce().expect("Failed to generate nonce");
//! ```
//!
//! ## Integration with Memora
//!
//! `memrand` is used throughout the Memora stack:
//! - **memaead**: Key and nonce generation for AEAD encryption
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
pub use session::NonceSessionGenerator;
pub use system::SystemEntropySource;
pub use traits::{EntropySource, NonceGenerator};

#[cfg(any(test, feature = "test_utils"))]
pub use support::test_utils;
