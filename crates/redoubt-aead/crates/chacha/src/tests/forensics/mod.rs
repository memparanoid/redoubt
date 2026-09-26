// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a keystream laid over a buffer leaves behind of the key and the
//! message, and what a derivation leaves of the key and the subkey.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

mod support;

mod chacha20;
mod hchacha20;
mod xchacha20;
