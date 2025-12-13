// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memzer
//!
//! RAII guards and systematic zeroization for protecting sensitive data in memory.
//!
//! This is a re-export crate that combines [`memzer-core`] and [`memzer-derive`] for convenience.
//!
//! ## Quick Start
//!
//! ```rust
//! use memzer::{ZeroizeOnDropSentinel, FastZeroizable, ZeroizationProbe, AssertZeroizeOnDrop, MemZer};
//!
//! #[derive(MemZer)]
//! #[memzer(drop)]
//! struct ApiKey {
//!     key: Vec<u8>,
//!     __sentinel: ZeroizeOnDropSentinel,
//! }
//!
//! let api_key = ApiKey {
//!     key: b"sk_live_...".to_vec(),
//!     __sentinel: ZeroizeOnDropSentinel::default(),
//! };
//!
//! // Verify zeroization happens on drop
//! api_key.assert_zeroize_on_drop();
//! ```
//!
//! ## What's Included
//!
//! - **Core types**: [`ZeroizeOnDropSentinel`], [`ZeroizingMutGuard`]
//! - **Traits**: [`FastZeroize`], [`FastZeroizable`], [`ZeroizeMetadata`], [`ZeroizationProbe`], [`AssertZeroizeOnDrop`], [`MutGuarded`]
//! - **Derive macro**: `#[derive(MemZer)]` for automatic trait implementations
//! - **Primitives**: Wrapper types for scalars (`U8`, `U16`, `U32`, `U64`, `U128`, `USIZE`)
//! - **Test helpers**: [`assert_zeroize_on_drop()`](assert::assert_zeroize_on_drop)
//!
//! For high-level wrappers like `Secret<T>`, see the `memsecret` crate.
//!
//! ## Documentation
//!
//! See [`memzer-core`] for detailed documentation and examples.
//!
//! [`memzer-core`]: https://docs.rs/memzer-core
//! [`memzer-derive`]: https://docs.rs/memzer-derive
//! [`ZeroizeOnDropSentinel`]: memzer_core::ZeroizeOnDropSentinel
//! [`ZeroizingMutGuard`]: memzer_core::ZeroizingMutGuard
//! [`FastZeroize`]: memzer_core::FastZeroize
//! [`FastZeroizable`]: memzer_core::FastZeroizable
//! [`ZeroizeMetadata`]: memzer_core::ZeroizeMetadata
//! [`ZeroizationProbe`]: memzer_core::ZeroizationProbe
//! [`AssertZeroizeOnDrop`]: memzer_core::AssertZeroizeOnDrop
//! [`MutGuarded`]: memzer_core::MutGuarded// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
#![cfg_attr(not(test), no_std)]

#[cfg(test)]
mod tests;

pub use memzer_core::*;
pub use memzer_derive::*;
