// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ProtectedBuffer - Unix protected memory buffer
//!
//! Uses mmap for allocation, mlock to prevent swapping,
//! and mprotect to control access (best-effort).

use core::ptr;

use memzer::{
    AssertZeroizeOnDrop, DropSentinel, FastZeroizable, ZeroizationProbe, ZeroizeMetadata,
};

pub struct ProtectedBuffer {
    ptr: *mut u8,
    len: usize,
    capacity: usize,
    mlock: bool,
    mprotect: bool,
    __drop_sentinel: DropSentinel,
}

// Safety: The buffer owns its memory and controls access
unsafe impl Send for ProtectedBuffer {}
unsafe impl Sync for ProtectedBuffer {}

impl ProtectedBuffer {
    pub fn try_create() -> Option<Self> {
        let capacity = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return None;
        }

        let ptr = ptr as *mut u8;

        Some(Self {
            ptr,
            len: 0,
            mlock: false,
            mprotect: false,
            capacity: page_size,
            __drop_sentinel: DropSentinel::default(),
        })
    }

    pub fn open_mut(&self) -> &mut [u8] {
        if self.mprotect {
            unsafe {
                libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_READ);
            }
        }

        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Close read access to the buffer.
    pub fn close_read(&self) {
        if self.mprotect {
            unsafe {
                libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_NONE);
            }
        }
    }

    /// Get the raw pointer (for serialization).
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Get the length of data in the buffer.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check if mlock succeeded.
    pub fn is_mlocked(&self) -> bool {
        self.mlock
    }
}

impl FastZeroizable for ProtectedBuffer {
    fn fast_zeroize(&mut self) {
        unsafe {
            ptr::write_volatile(&mut self.ptr, ptr::null_mut());
        }

        self.len.fast_zeroize();
        self.capacity.fast_zeroize();
        self.mlock.fast_zeroize();
        self.mprotect.fast_zeroize();
        self.__drop_sentinel.fast_zeroize();
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        unsafe {
            if self.mprotect {
                libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_WRITE);
            }

            core::ptr::write_bytes(self.ptr, 0, self.capacity); // zeroize
            libc::munlock(self.ptr as *const _, self.capacity);
            libc::munmap(self.ptr as *mut _, self.capacity);
        }

        self.fast_zeroize();
    }
}
