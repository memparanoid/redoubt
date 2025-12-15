// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # redoubt_rand
//!
//! Cryptographically secure random number generation for the Redoubt framework.
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
//! use redoubt_rand::{SystemEntropySource, NonceSessionGenerator, NonceGenerator, EntropySource};
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
//! ## Integration with Redoubt
//!
//! `redoubt_rand` is used throughout the Redoubt stack:
//! - **redoubt-aead**: Key and nonce generation for AEAD encryption
//! - **redoubt-vault**: Entropy for master key derivation
//!
//! ## Platform Support
//!
//! Supports all platforms via `getrandom`:
//! - Linux/Android: `getrandom()` syscall
//! - macOS/iOS: `getentropy()`
//! - Windows: `BCryptGenRandom`
//! - WASI: `random_get`

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(test)]
mod tests;

mod error;
mod session;
mod support;
mod system;
mod traits;

pub mod u64_seed;

pub use error::EntropyError;
pub use session::NonceSessionGenerator;
pub use system::SystemEntropySource;
pub use traits::{EntropySource, NonceGenerator};

#[cfg(any(test, feature = "test_utils"))]
pub use support::test_utils;
