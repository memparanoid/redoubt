// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a derivation leaves behind, through the backend the target chose.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

mod support;

mod hkdf;
