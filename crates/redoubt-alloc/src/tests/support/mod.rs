// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[global_allocator]
static ALLOCATOR: redoubt_forensics::ForensicsAllocator<std::alloc::System> =
    redoubt_forensics::ForensicsAllocator::new(std::alloc::System);

/// Every byte of an allocation, past the length included.
///
/// # Safety
///
/// `ptr` the start of an allocation of `capacity` bytes, every one of them
/// written.
pub(crate) unsafe fn capacity_is_zeroized(ptr: *const u8, capacity: usize) -> bool {
    // SAFETY: the caller's, verbatim.
    let whole = unsafe { core::slice::from_raw_parts(ptr, capacity) };

    whole.iter().all(|byte| *byte == 0)
}
