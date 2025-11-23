// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memzer-core
//!
//! RAII guards and systematic zeroization primitives for protecting sensitive data in memory.
//!
//! `memzer-core` provides composable building blocks for secure memory handling:
//!
//! - **[`DropSentinel`]**: Runtime verification that zeroization happened before drop
//! - **[`ZeroizingMutGuard`]**: RAII guard for mutable references (auto-zeroizes on drop)
//! - **Traits**: [`Zeroizable`], [`ZeroizationProbe`], [`AssertZeroizeOnDrop`], [`MutGuarded`]
//! - **Derive macro**: `#[derive(MemZer)]` for automatic trait implementations
//!
//! For high-level wrappers, see the `memsecret` crate which provides `Secret<T>` and `MemMove`.
//!
//! ## Core Problem
//!
//!
//!
//!
//!
//!
//!
//!
//! ## Design Principles
//!
//! 1. **Systematic zeroization**: Guards auto-zeroize on drop (impossible to forget)
//! 2. **Runtime verification**: [`DropSentinel`] ensures zeroization happened
//! 3. **API safety**: High-level wrappers (like `memsecret::Secret<T>`) prevent direct access
//! 4. **Composability**: Traits work with collections, nested types, custom structs
//!
//! ## Quick Start
//!
//! ### Using `ZeroizingMutGuard`
//!
//! ```rust
//! use memzer_core::{ZeroizingMutGuard, ZeroizationProbe, primitives::U64};
//!
//! let mut sensitive = U64::default();
//! *sensitive.expose_mut() = 0xdeadbeef;
//!
//! {
//!     // Guard zeroizes `sensitive` when dropped
//!     let mut guard = ZeroizingMutGuard::from(&mut sensitive);
//!     *guard.expose_mut() = 0xcafebabe;
//! } // guard drops here → sensitive is zeroized
//!
//! assert!(sensitive.is_zeroized());
//! ```
//!
//! ### Manual Implementation
//!
//! ```rust
//! use memzer_core::{DropSentinel, Zeroizable, ZeroizationProbe, AssertZeroizeOnDrop, collections};
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! #[zeroize(drop)]
//! struct Credentials {
//!     username: Vec<u8>,
//!     password: Vec<u8>,
//!     __drop_sentinel: DropSentinel,
//! }
//!
//! impl Zeroizable for Credentials {
//!     fn self_zeroize(&mut self) {
//!         self.zeroize();
//!     }
//! }
//!
//! impl ZeroizationProbe for Credentials {
//!     fn is_zeroized(&self) -> bool {
//!         let fields: [&dyn ZeroizationProbe; 2] = [
//!             collections::to_zeroization_probe_dyn_ref(&self.username),
//!             collections::to_zeroization_probe_dyn_ref(&self.password),
//!         ];
//!         collections::collection_zeroed(&mut fields.into_iter())
//!     }
//! }
//!
//! impl AssertZeroizeOnDrop for Credentials {
//!     fn clone_drop_sentinel(&self) -> DropSentinel {
//!         self.__drop_sentinel.clone()
//!     }
//!     fn assert_zeroize_on_drop(self) {
//!         memzer_core::assert::assert_zeroize_on_drop(self);
//!     }
//! }
//!
//! let creds = Credentials {
//!     username: b"admin".to_vec(),
//!     password: b"secret".to_vec(),
//!     __drop_sentinel: DropSentinel::default(),
//! };
//!
//! // Verify zeroization happens on drop
//! creds.assert_zeroize_on_drop(); // ✅ Passes
//! ```
//!
//! ## Module Organization
//!
//! - [`drop_sentinel`]: Drop verification mechanism
//! - [`assert`](mod@assert): Test helpers for verifying zeroization behavior
//! - [`collections`]: Trait impls and helpers for slices, arrays, `Vec<T>`
//! - [`primitives`]: Wrapper types for scalars (`U8`, `U16`, `U32`, `U64`, `U128`, `USIZE`)
//!
//! ## Integration with Memora
//!
//! `memzer-core` is a foundational crate in the **Memora** framework:
//!
//! ```text
//! memvault (encrypted storage)
//!     ├─> memcrypt (AEAD encryption) ──> guards from memzer
//!     └─> memcode (serialization) ────> guards from memzer
//!         └─> memzer (this crate)
//! ```
//!
//! Guards compose with other Memora crates:
//! - **memsecret**: High-level `Secret<T>` wrapper built on memzer traits
//! - **memcode**: Serialization support for guards (via `memcode` feature)
//! - **memcrypt**: Encryption stages use [`ZeroizingMutGuard`] for keys/nonces
//! - **memvault**: High-level API uses guards for encrypted in-memory storage
//!
//! ## Feature Flags
//!
//! - `memcode`: Enable integration with `memcode-core` (serialization support for guards)
//!
//! ## Safety
//!
//! This crate uses `#![warn(unsafe_op_in_unsafe_fn)]` and minimizes `unsafe` usage.
//! All guards rely on RAII (Drop trait) for safety guarantees.
//!
//! ## License
//!
//! GPL-3.0-only
//!
//! [`zeroize`]: https://docs.rs/zeroize
//!

#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
mod tests;

/// Drop verification mechanism for ensuring zeroization happened before drop.
///
/// Contains [`DropSentinel`], the core type used to verify that `.zeroize()` was called.
mod drop_sentinel;
mod traits;
mod zeroizing_mut_guard;

/// Test helpers for verifying zeroization behavior in tests.
///
/// Primary export: [`assert_zeroize_on_drop()`](self::assert::assert_zeroize_on_drop).
#[allow(clippy::module_name_repetitions)]
pub mod assert;

/// Trait implementations and helpers for collections (slices, arrays, `Vec<T>`).
///
/// Provides [`Zeroizable`] and [`ZeroizationProbe`] implementations for standard collection types.
pub mod collections;

/// Wrapper types for primitive scalars with [`DropSentinel`] support.
///
/// Exports: `U8`, `U16`, `U32`, `U64`, `U128`, `USIZE` - each wraps the corresponding primitive type.
pub mod primitives;
pub use drop_sentinel::DropSentinel;
pub use traits::{AssertZeroizeOnDrop, MutGuarded, Zeroizable, ZeroizationProbe};
pub use zeroizing_mut_guard::ZeroizingMutGuard;

#[cfg(any(test, feature = "memcode"))]
mod mem_encode_buf;

#[cfg(any(test, feature = "memcode"))]
pub use mem_encode_buf::MemEncodeBuf;
