// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the facade leaves behind, measured through the API a caller has.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

#![cfg(target_os = "linux")]

mod support;

mod cipherbox;
mod cipherbox_halves;
