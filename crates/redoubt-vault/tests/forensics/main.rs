// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the facade leaves behind, measured through the API a caller has.
//!
//! # One binary, and a process each anyway
//!
//! A directory under `tests/` is one target and not one per file, so both
//! modules below are linked together. That costs nothing here: `nextest` gives
//! every test function its own process, which is what these need — the memory
//! being read is the whole process's, so a second test sharing it is another
//! place the secret could be and another test's needle to trip over.

#![cfg(target_os = "linux")]

mod cipherbox;
mod cipherbox_halves;
