// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The allocator of every test in this binary: each block it hands out is
//! filled with `DIRT`, save the ones asked for zeroed.
//!
//! The system allocator hands out a block as its last owner left it, or empty
//! when the kernel gives it a fresh page, and which one depends on the libc and
//! the target. A test asking whether new capacity reads zero could pass by that
//! chance; under this one it cannot.
//!
//! Addresses, sizes and reuse are still `System`'s. What changes is only what
//! memory nobody initialised holds, and code that never reads it behaves the
//! same under either.

use std::alloc::{GlobalAlloc, Layout, System};

const DIRT: u8 = 0xFF;

struct DirtyAllocator;

// SAFETY: every call is forwarded to `System` with the layout it was given, and
// what is written afterwards stays inside the block `System` handed back.
unsafe impl GlobalAlloc for DirtyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the layout is the caller's, which `GlobalAlloc::alloc` asks
        // to be valid and of a size above zero.
        let block = unsafe { System.alloc(layout) };

        if !block.is_null() {
            // SAFETY: `System` handed back a block of `layout.size()` bytes.
            unsafe { core::ptr::write_bytes(block, DIRT, layout.size()) };
        }

        block
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the layout is the caller's, as in `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: `block` came from `alloc` or `realloc` here, which are
        // `System`'s, with this layout.
        unsafe { System.dealloc(block, layout) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `block` and `layout` are as in `dealloc`, and `new_size` is
        // the caller's, which `GlobalAlloc::realloc` asks to be valid.
        let grown = unsafe { System.realloc(block, layout, new_size) };

        if !grown.is_null() && new_size > layout.size() {
            // SAFETY: the block holds `new_size` bytes, and what is written
            // starts past the `layout.size()` the caller's bytes take.
            unsafe {
                core::ptr::write_bytes(grown.add(layout.size()), DIRT, new_size - layout.size())
            };
        }

        grown
    }
}

#[global_allocator]
static DIRTY: DirtyAllocator = DirtyAllocator;

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::DIRT;

    fn whole_capacity(vec: &Vec<u8>) -> &[u8] {
        // SAFETY: the pointer and the count come from the same `Vec`, and every
        // byte of its block was written, by the allocator or by the test.
        unsafe { core::slice::from_raw_parts(vec.as_ptr(), vec.capacity()) }
    }

    #[test]
    fn test_alloc_hands_out_a_dirty_block() {
        let vec = Vec::<u8>::with_capacity(4096);

        assert!(whole_capacity(&vec).iter().all(|&byte| byte == DIRT));
    }

    #[test]
    fn test_alloc_zeroed_hands_out_a_zeroed_block() {
        let vec = std::vec![0_u8; 4096];

        assert!(whole_capacity(&vec).iter().all(|&byte| byte == 0));
    }

    #[test]
    fn test_realloc_keeps_what_was_held_and_dirties_what_it_grows_into() {
        let mut vec = std::vec![0xAB_u8; 16];

        vec.reserve_exact(4096);

        let (held, grown) = whole_capacity(&vec).split_at(16);

        assert!(held.iter().all(|&byte| byte == 0xAB));
        assert!(grown.iter().all(|&byte| byte == DIRT));
    }
}
