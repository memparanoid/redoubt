// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # Memrand
//!
//! random number generation utilities for Memora framework

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
