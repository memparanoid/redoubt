// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Systematic memory zeroization with compile-time and runtime guarantees.
//!
//! # Overview
//!
//! **redoubt-zero** provides RAII guards and derive macros for automatic, verifiable zeroization.
//! Zeroization happens automatically on drop with runtime verification that it actually occurred.
//!
//! This is a convenience re-export crate combining [`redoubt-zero-core`] and [`redoubt-zero-derive`].
//!
//! # Quick Start
//!
//! ```rust
//! use redoubt_zero::{RedoubtZero, ZeroizeOnDropSentinel, AssertZeroizeOnDrop};
//!
//! #[derive(RedoubtZero)]
//! #[fast_zeroize(drop)]
//! struct TempBuffer {
//!     data: Vec<u8>,
//!     capacity: usize,
//!     __sentinel: ZeroizeOnDropSentinel,
//! }
//!
//! let mut buffer = TempBuffer {
//!     data: vec![1, 2, 3, 4],
//!     capacity: 1024,
//!     __sentinel: ZeroizeOnDropSentinel::default(),
//! };
//!
//! // Use buffer...
//!
//! // Automatically zeroized on drop
//! drop(buffer);
//! ```
//!
//! # How It Works
//!
//! ## 1. The Sentinel Pattern
//!
//! Every struct includes a [`ZeroizeOnDropSentinel`] field. This sentinel:
//! - Flips a flag on drop
//! - Can be cloned to verify the original was zeroized
//! - Provides runtime proof of zeroization
//!
//! ## 2. Automatic Trait Implementation
//!
//! The `#[derive(RedoubtZero)]` macro generates:
//!
//! - **[`FastZeroizable`]**: Implements `fast_zeroize(&mut self)` to zero all fields
//! - **[`ZeroizationProbe`]**: Implements `is_zeroized(&self)` to check if data is zeroed
//! - **[`AssertZeroizeOnDrop`]**: Test helper to verify drop behavior
//! - **Optional Drop impl**: With `#[fast_zeroize(drop)]`, generates `Drop` that calls `fast_zeroize()`
//!
//! ## 3. Field Skipping
//!
//! Fields can be excluded from zeroization with `#[fast_zeroize(skip)]`:
//!
//! ```rust
//! # use redoubt_zero::{RedoubtZero, ZeroizeOnDropSentinel};
//! #[derive(RedoubtZero)]
//! struct SessionData {
//!     token: Vec<u8>,        // Zeroized
//!     #[fast_zeroize(skip)]
//!     id: u64,               // Not zeroized (just metadata)
//!     __sentinel: ZeroizeOnDropSentinel,
//! }
//! ```
//!
//! # Core Types
//!
//! - **[`ZeroizeOnDropSentinel`]**: Drop sentinel for verifiable zeroization
//! - **[`ZeroizingGuard<T>`]**: RAII wrapper that zeroizes on drop (owned)
//! - **[`ZeroizingMutGuard<'a, T>`]**: RAII wrapper that zeroizes on drop (borrowed)
//!
//! # Traits
//!
//! - **[`FastZeroizable`]**: Provides `fast_zeroize(&mut self)` for efficient zeroization
//! - **[`ZeroizationProbe`]**: Provides `is_zeroized(&self)` to check if data is zeroed
//! - **[`AssertZeroizeOnDrop`]**: Test helper to verify drop zeroization
//! - **[`ZeroizeMetadata`]**: Field count metadata for verification
//!
//! # Testing Zeroization
//!
//! Use [`AssertZeroizeOnDrop::assert_zeroize_on_drop()`] in tests to verify behavior:
//!
//! ```rust
//! # use redoubt_zero::{RedoubtZero, ZeroizeOnDropSentinel, AssertZeroizeOnDrop};
//! #[derive(RedoubtZero)]
//! #[fast_zeroize(drop)]
//! struct Workspace {
//!     buffer: Vec<u8>,
//!     __sentinel: ZeroizeOnDropSentinel,
//! }
//!
//! #[test]
//! fn test_workspace_zeroizes() {
//!     let ws = Workspace {
//!         buffer: vec![1, 2, 3, 4],
//!         __sentinel: ZeroizeOnDropSentinel::default(),
//!     };
//!     ws.assert_zeroize_on_drop();  // Panics if not zeroized
//! }
//! ```
//!
//! # Design Rationale
//!
//! ## The Sentinel Pattern
//!
//! The sentinel enables runtime verification without unsafe code:
//! - Clone the sentinel before drop
//! - Drop the original
//! - Check the sentinel's flag flipped
//!
//! This proves `Drop` ran and zeroization occurred.
//!
//! ## FastZeroizable Implementation
//!
//! `FastZeroizable` uses compiler fences for zeroization:
//! - Matches LLVM's optimization model
//! - Allows vectorization and unrolling
//! - Prevents dead store elimination
//!
//! See [`redoubt-zero-core`](redoubt_zero_core) for implementation details.
//!
//! # Use Cases
//!
//! Useful for any data that needs guaranteed cleanup:
//!
//! - **Cryptographic material**: Keys, nonces, IVs
//! - **Temporary buffers**: Workspace memory, intermediate results
//! - **Session data**: Tokens, cookies, auth state
//! - **Parser state**: Untrusted input, partial parses
//! - **Any heap allocation** you want cleaned up reliably
//!
//! # Crate Structure
//!
//! This crate re-exports:
//! - [`redoubt-zero-core`](redoubt_zero_core): Core types and traits
//! - [`redoubt-zero-derive`](redoubt_zero_derive): `#[derive(RedoubtZero)]` macro
//!
//! [`ZeroizeOnDropSentinel`]: redoubt_zero_core::ZeroizeOnDropSentinel
//! [`ZeroizingGuard<T>`]: redoubt_zero_core::ZeroizingGuard
//! [`ZeroizingMutGuard<'a, T>`]: redoubt_zero_core::ZeroizingMutGuard
//! [`FastZeroizable`]: redoubt_zero_core::FastZeroizable
//! [`ZeroizationProbe`]: redoubt_zero_core::ZeroizationProbe
//! [`AssertZeroizeOnDrop`]: redoubt_zero_core::AssertZeroizeOnDrop
//! [`ZeroizeMetadata`]: redoubt_zero_core::ZeroizeMetadata
//! [`AssertZeroizeOnDrop::assert_zeroize_on_drop()`]: redoubt_zero_core::AssertZeroizeOnDrop::assert_zeroize_on_drop
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
mod tests;

pub use redoubt_zero_core::*;
pub use redoubt_zero_derive::*;
