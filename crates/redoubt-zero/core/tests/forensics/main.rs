// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the guards leave behind between taking a value and dropping it.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

#![cfg(target_os = "linux")]

mod support;

mod zeroizing_guard;
mod zeroizing_mut_guard;
