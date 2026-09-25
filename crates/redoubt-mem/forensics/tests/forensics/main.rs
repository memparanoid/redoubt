// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each copy, swap and check leaves behind, weighed over the whole register file
//! rather than over the registers the assembly names.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

#![cfg(target_os = "linux")]

mod support;

mod copy;
mod swap;
mod utf8;
mod zeroized;
