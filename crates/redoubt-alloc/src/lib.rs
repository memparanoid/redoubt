// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Secure allocation containers with automatic zeroization.
//!
//! This crate provides four main types:
//!
//! - [`AllockedVec`]: Capacity-locked Vec with fallible operations
//! - [`RedoubtArray`]: Fixed-size array with automatic zeroization
//! - [`RedoubtVec`]: Auto-growing Vec with safe reallocation (2x growth)
//! - [`RedoubtString`]: Auto-growing String with safe reallocation (2x growth)
//!
//! # Core Guarantees
//!
//! - **Controlled capacity**: Once sealed with `reserve_exact()`, that method cannot be called
//!   again. To change capacity, use `realloc_with_capacity()` which safely zeroizes the old
//!   allocation before creating a new one.
//! - **Automatic zeroization**: All data is zeroized on drop via `#[fast_zeroize(drop)]`
//! - **Fallible operations**: `push()` and `reserve_exact()` fail instead of reallocating,
//!   preventing unintended copies of data
//!
//! # Example: Basic Usage
//!
//! ```rust
//! use redoubt_alloc::{AllockedVec, AllockedVecError};
//!
//! fn example() -> Result<(), AllockedVecError> {
//!     let mut vec = AllockedVec::<u8>::new();
//!     vec.reserve_exact(10)?;
//!
//!     // Now sealed - cannot reserve again
//!     assert!(vec.reserve_exact(20).is_err());
//!
//!     // Push works while capacity allows
//!     for i in 0u8..10 {
//!         vec.push(i)?;
//!     }
//!
//!     // Exceeding capacity fails
//!     assert!(vec.push(42).is_err());
//!     Ok(())
//! }
//! # example().unwrap();
//! ```
//!
//! # Example: Controlled Reallocation
//!
//! ```rust
//! use redoubt_alloc::{AllockedVec, AllockedVecError};
//!
//! fn example() -> Result<(), AllockedVecError> {
//!     let mut vec = AllockedVec::<u8>::with_capacity(5);
//!     vec.push(1)?;
//!     vec.push(2)?;
//!
//!     // Change capacity with realloc_with_capacity()
//!     // This zeroizes the old allocation before creating the new one
//!     vec.realloc_with_capacity(10);
//!
//!     for i in 3u8..=10 {
//!         vec.push(i)?;
//!     }
//!
//!     assert_eq!(vec.len(), 10);
//!     assert_eq!(vec.capacity(), 10);
//!     Ok(())
//! }
//! # example().unwrap();
//! ```
//!
//! # Test Utilities
//!
//! Enable the `test_utils` feature to inject failures for testing error handling paths:
//!
//! ```toml
//! [dev-dependencies]
//! redoubt-alloc = { version = "*", features = ["test_utils"] }
//! ```
//!
//! Then use [`AllockedVecBehaviour`] to test error scenarios:
//!
//! ```rust
//! // test_utils feature required in dev-dependencies
//! #[cfg(test)]
//! mod tests {
//!     use redoubt_alloc::{AllockedVec, AllockedVecBehaviour};
//!
//!     #[test]
//!     fn test_handles_push_failure() {
//!         let mut vec = AllockedVec::with_capacity(10);
//!         vec.change_behaviour(AllockedVecBehaviour::FailAtPush);
//!
//!         // Test that your code handles the error correctly
//!         assert!(vec.push(1u8).is_err());
//!     }
//! }
//! ```

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod allocked_vec;
mod error;
mod redoubt_array;
mod redoubt_option;
mod redoubt_string;
mod redoubt_vec;

#[cfg(test)]
mod tests;

pub use allocked_vec::AllockedVec;
pub use error::{AllockedVecError, RedoubtOptionError};
pub use redoubt_array::RedoubtArray;
pub use redoubt_option::RedoubtOption;
pub use redoubt_string::RedoubtString;
pub use redoubt_vec::RedoubtVec;

#[cfg(any(test, feature = "test_utils"))]
pub use allocked_vec::AllockedVecBehaviour;
