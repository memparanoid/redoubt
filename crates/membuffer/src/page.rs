// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Page - Low-level memory page with protection primitives.
//!
//! Wraps a single mmap'd page with mlock/mprotect operations.
//! Each syscall is exposed separately for granular testing.

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use memzer::FastZeroizable;

use super::error::PageError;

/// A memory page with protection primitives.
///
/// Provides granular control over mmap/mlock/mprotect.
/// Tracks protection state internally via AtomicBool.
#[derive(Debug)]
pub struct Page {
    ptr: *mut u8,
    capacity: usize,
    is_protected: AtomicBool,
}

unsafe impl Send for Page {}
unsafe impl Sync for Page {}

impl Page {
    /// Allocates a new page via mmap. Does NOT lock or protect.
    pub fn new() -> Result<Self, PageError> {
        let capacity = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                capacity,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(PageError::CreationFailed);
        }

        let mut page = Self {
            capacity,
            ptr: ptr as *mut u8,
            is_protected: AtomicBool::new(false),
        };

        unsafe { page.zeroize() };

        Ok(page)
    }

    /// Locks page in RAM (prevents swapping to disk).
    pub fn lock(&self) -> Result<(), PageError> {
        let failed = unsafe { libc::mlock(self.ptr as *const _, self.capacity) } != 0;

        if failed {
            return Err(PageError::LockFailed);
        }

        Ok(())
    }

    /// Sets page to PROT_NONE (no read/write access).
    pub fn protect(&self) -> Result<(), PageError> {
        let failed =
            unsafe { libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_NONE) } != 0;

        if failed {
            return Err(PageError::ProtectionFailed);
        }

        self.is_protected.store(true, Ordering::Release);

        Ok(())
    }

    /// Sets page to PROT_WRITE (allows write access).
    pub fn unprotect(&self) -> Result<(), PageError> {
        let failed =
            unsafe { libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_WRITE) } != 0;

        if failed {
            return Err(PageError::UnprotectionFailed);
        }

        self.is_protected.store(false, Ordering::Release);

        Ok(())
    }

    /// Returns a slice view of the page. Caller must ensure page is unprotected.
    ///
    /// # Safety
    /// Page must be unprotected (PROT_READ or PROT_WRITE), otherwise SIGSEGV.
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.capacity) }
    }

    /// Returns a mutable slice view of the page. Caller must ensure page is unprotected.
    ///
    /// # Safety
    /// Page must be unprotected (PROT_WRITE), otherwise SIGSEGV.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.capacity) }
    }

    /// Zeroizes the page contents. Page must be unprotected.
    ///
    /// # Safety
    /// Page must be unprotected (PROT_WRITE), otherwise SIGSEGV.
    pub unsafe fn zeroize(&mut self) {
        unsafe { self.as_mut_slice().fast_zeroize() };
    }

    /// Unlocks page (allows swapping). Called in Drop.
    pub fn munlock(&self) {
        unsafe { libc::munlock(self.ptr as *const _, self.capacity) };
    }

    pub fn dispose(&mut self) {
        // Best effort: try to unprotect and zeroize before unmapping
        // If unprotect fails, page stays protected (safe)
        if self.is_protected.load(Ordering::Acquire) {
            let _ = self.unprotect();
        }

        // If we can write, zeroize
        if !self.is_protected.load(Ordering::Acquire) {
            unsafe { self.zeroize() };
        }

        self.munlock();
        self.munmap();
    }

    /// Unmaps the page. Called in Drop.
    fn munmap(&self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.capacity) };
    }
}
