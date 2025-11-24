// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Allocation-locked Vec that guarantees no reallocation after sealing.
//!
//! `AllockedVec<T>` is a wrapper around `Vec<T>` that prevents reallocation after the initial
//! capacity is set. This is critical for sensitive data to ensure:
//!
//! - **No reallocation**: Once sealed, the Vec cannot grow beyond its capacity
//! - **Automatic zeroization**: Data is zeroized on drop via `#[zeroize(drop)]`
//! - **Fail-safe operations**: `push()` and `reserve_exact()` are fallible and zeroize on error
//!
//! # Example
//!
//! ```rust
//! use memalloc::AllockedVec;
//!
//! let mut vec = AllockedVec::<u8>::new();
//! vec.reserve_exact(10).expect("reserve failed");
//!
//! // Now sealed - cannot reserve again
//! assert!(vec.reserve_exact(20).is_err());
//!
//! // Push works while capacity allows
//! for i in 0u8..10 {
//!     vec.push(i).expect("push failed");
//! }
//!
//! // Exceeding capacity fails and zeroizes
//! assert!(vec.push(42).is_err());
//! ```

mod vec;

#[cfg(test)]
mod tests;

pub use vec::{AllockedVec, AllockedVecError};
