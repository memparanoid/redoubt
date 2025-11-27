// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Secure buffer with locked capacity and automatic zeroization.
use zeroize::Zeroize;

use memalloc::AllockedVec;
use memzer::{AssertZeroizeOnDrop, DropSentinel, ZeroizationProbe, assert::assert_zeroize_on_drop};

pub struct Buffer {
    pub ptr: *mut u8,
    pub end: *mut u8,
    pub cursor: *mut u8,
    allocked_vec: AllockedVec<u8>,
    __drop_sentinel: DropSentinel,
}

impl Zeroize for Buffer {
    fn zeroize(&mut self) {
        unsafe {
            core::ptr::write_volatile(&mut self.ptr, core::ptr::null_mut());
            core::ptr::write_volatile(&mut self.cursor, core::ptr::null_mut());
        }
        self.allocked_vec.zeroize();
        self.__drop_sentinel.zeroize();
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl AssertZeroizeOnDrop for Buffer {
    fn clone_drop_sentinel(&self) -> DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl ZeroizationProbe for Buffer {
    fn is_zeroized(&self) -> bool {
        (self.ptr == core::ptr::null_mut())
            & (self.cursor == core::ptr::null_mut())
            & self.allocked_vec.is_zeroized()
            & self.__drop_sentinel.is_zeroized()
    }
}

impl Buffer {
    pub fn new(capacity: usize) -> Self {
        let mut allocked_vec = AllockedVec::<u8>::with_capacity(capacity);
        let ptr = allocked_vec.as_mut_ptr();
        let end = unsafe { ptr.add(capacity) };
        let cursor = ptr.clone();

        Self {
            ptr,
            end,
            cursor,
            allocked_vec,
            __drop_sentinel: DropSentinel::default(),
        }
    }

    pub fn clear(&mut self) {
        self.cursor = self.ptr.clone();
        self.allocked_vec.zeroize();
    }

    pub fn as_slice(&self) -> &[u8] {
        self.allocked_vec.as_capacity_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.allocked_vec.as_capacity_mut_slice()
    }
}
