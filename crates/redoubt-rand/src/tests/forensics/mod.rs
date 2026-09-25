// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What asking for random bytes leaves behind.
//!
//! The bytes do not exist until the call produces them, so the watch is built
//! after the capture, and nothing photographs the process before it: an
//! absence here asserts no copy and no run wider than `QUIET`, not an unmoved
//! score.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

mod support;

mod fill;
mod session;
mod system;
