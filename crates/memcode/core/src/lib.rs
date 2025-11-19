// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # memcode-core
//!
//! Core serialization traits with automatic zeroization.
//!
//! This crate provides the foundational traits and implementations for
//! memory-safe serialization that automatically zeros sensitive data.

#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]
