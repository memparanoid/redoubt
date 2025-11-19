// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memzer-core
//!
//! Core primitives for protected memory guards and sentinels.
//!
//! This crate provides the foundational types for automatic memory
//! zeroization and protected memory regions.

#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

pub use zeroize::{Zeroize, ZeroizeOnDrop};
