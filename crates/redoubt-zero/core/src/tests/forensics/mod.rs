// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the zeroizers, the probes and the guards leave behind.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

mod support;

mod atomics;
mod collections;
mod pointers;
mod primitives;
mod zeroizing_guard;
mod zeroizing_mut_guard;
