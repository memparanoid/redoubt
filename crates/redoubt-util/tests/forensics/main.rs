// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the wipers leave behind once they have run and let go.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

#![cfg(target_os = "linux")]

mod zeroize;

#[global_allocator]
static ALLOCATOR: redoubt_forensics::ForensicsAllocator<std::alloc::System> =
    redoubt_forensics::ForensicsAllocator::new(std::alloc::System);
