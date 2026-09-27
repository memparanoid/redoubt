// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::alloc::System;

use redoubt_forensics_core::ForensicsAllocator;

#[global_allocator]
static ALLOCATOR: ForensicsAllocator<System> = ForensicsAllocator::new(System);

/// The byte the attribute below is given, written there again because an
/// attribute takes a literal and not a constant.
const DIRT: u8 = 0xFC;

// ============================================================================
// test
// ============================================================================

#[redoubt_forensics_macros::test(dirty = 0xFC)]
fn test_test_enables_the_allocator_with_the_dirt_it_is_given() {
    let fresh = Vec::<u8>::with_capacity(4096);

    // SAFETY: the pointer and the capacity are `fresh`'s own, and every byte of
    // its block was written by the allocator with the dirt.
    let whole = unsafe { core::slice::from_raw_parts(fresh.as_ptr(), fresh.capacity()) };

    assert!(whole.iter().all(|&byte| byte == DIRT));
}
