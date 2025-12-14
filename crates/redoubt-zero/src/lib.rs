// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # RedoubtZero
//!
//! RAII guards and systematic zeroization for protecting sensitive data in memory.
//!
//! This is a re-export crate that combines [`RedoubtZero-core`] and [`RedoubtZero-derive`] for convenience.
//!
//! ## Quick Start
//!
//! ```rust
//! use redoubt_zero::{RedoubtZero, ZeroizeOnDropSentinel, FastZeroizable, ZeroizationProbe, AssertZeroizeOnDrop};
//!
//! #[derive(RedoubtZero)]
//! #[fast_zeroize(drop)]
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
//! - **Derive macro**: `#[derive(RedoubtZero)]` for automatic trait implementations
//! - **Primitives**: Wrapper types for scalars (`U8`, `U16`, `U32`, `U64`, `U128`, `USIZE`)
//! - **Test helpers**: [`assert_zeroize_on_drop()`](assert::assert_zeroize_on_drop)
//!
//! For high-level wrappers like `Secret<T>`, see the `memsecret` crate.
//!
//! ## Documentation
//!
//! See [`RedoubtZero-core`] for detailed documentation and examples.
//!
//! [`RedoubtZero-core`]: https://docs.rs/RedoubtZero-core
//! [`RedoubtZero-derive`]: https://docs.rs/RedoubtZero-derive
//! [`ZeroizeOnDropSentinel`]: redoubt_zero_core::ZeroizeOnDropSentinel
//! [`ZeroizingMutGuard`]: redoubt_zero_core::ZeroizingMutGuard
//! [`FastZeroize`]: redoubt_zero_core::FastZeroize
//! [`FastZeroizable`]: redoubt_zero_core::FastZeroizable
//! [`ZeroizeMetadata`]: redoubt_zero_core::ZeroizeMetadata
//! [`ZeroizationProbe`]: redoubt_zero_core::ZeroizationProbe
//! [`AssertZeroizeOnDrop`]: redoubt_zero_core::AssertZeroizeOnDrop
//! [`MutGuarded`]: redoubt_zero_core::MutGuarded

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
mod tests;

pub use redoubt_zero_core::*;
pub use redoubt_zero_derive::*;
