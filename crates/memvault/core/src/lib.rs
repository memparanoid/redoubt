// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memvault Core
//!
//! Core functionality for memvault.

#![cfg_attr(all(feature = "no_std", not(test)), no_std)]

mod error;
pub mod master_key;

pub use error::BufferError;

#[cfg(test)]
mod tests;
