// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Page - Low-level memory page with protection primitives.
//!
//! Wraps a single mmap'd page with mlock/mprotect operations.
//! Each syscall is exposed separately for granular testing.

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use redoubt_zero::FastZeroizable;

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
        // SAFETY: it reads a number the C library holds, takes no pointer and
        // writes nowhere.
        let capacity = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

        // SAFETY: a null address asks the kernel to choose one, and the fd is
        // -1 under `MAP_ANONYMOUS`, so nothing is mapped from a file. What
        // comes back is checked against `MAP_FAILED` below before it is used
        // as a pointer.
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
            return Err(PageError::Create);
        }

        let mut page = Self {
            capacity,
            ptr: ptr as *mut u8,
            is_protected: AtomicBool::new(false),
        };

        // SAFETY: what `zeroize` asks is that the page be writable, and the
        // mapping was just made `PROT_READ | PROT_WRITE` with nothing since to
        // protect it.
        unsafe { page.zeroize() };

        Ok(page)
    }

    /// Locks page in RAM (prevents swapping to disk).
    // Miri models `mmap` but not the operations that change a mapping's
    // properties. `mlock`, `mprotect`, `madvise` and `munlock` all abort the
    // interpreter as unsupported foreign calls, which puts every consumer of
    // this crate — the vault, and therefore the whole cipherbox — out of
    // Miri's reach.
    //
    // Reporting success without performing them keeps the pointer arithmetic,
    // the slice construction and the zeroization under scrutiny, which is the
    // part Miri can actually check. The syscalls themselves are the kernel's
    // contract, not this crate's, and no interpreter was going to verify them.
    pub fn lock(&self) -> Result<(), PageError> {
        #[cfg(miri)]
        return Ok(());

        #[cfg(not(miri))]
        {
            // SAFETY: the address and the length are the mapping's own, so the
            // range is one this process owns.
            let failed = unsafe { libc::mlock(self.ptr as *const _, self.capacity) } != 0;

            if failed {
                return Err(PageError::Lock);
            }

            Ok(())
        }
    }

    /// Marks page as non-dumpable (excludes from core dumps).
    #[cfg(target_os = "linux")]
    pub fn mark_dontdump(&self) -> Result<(), PageError> {
        #[cfg(miri)]
        return Ok(());

        #[cfg(not(miri))]
        {
            // SAFETY: the address and the length are the mapping's own, so the
            // range is one this process owns.
            let failed = unsafe {
                libc::madvise(
                    self.ptr as *mut libc::c_void,
                    self.capacity,
                    libc::MADV_DONTDUMP,
                )
            } != 0;

            if failed {
                return Err(PageError::Madvise);
            }

            Ok(())
        }
    }

    /// No-op on non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn mark_dontdump(&self) -> Result<(), PageError> {
        Ok(())
    }

    /// Sets page to PROT_NONE (no read/write access).
    pub fn protect(&self) -> Result<(), PageError> {
        #[cfg(not(miri))]
        {
            // SAFETY: the address and the length are the mapping's own, so the
            // range is one this process owns. Every way of reaching the bytes
            // is an `unsafe fn` asking the caller for a page it may read, so a
            // slice held across this is the caller's to answer for.
            let failed =
                unsafe { libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_NONE) } != 0;

            if failed {
                return Err(PageError::Protect);
            }
        }

        self.is_protected.store(true, Ordering::Release);

        Ok(())
    }

    /// Sets page to PROT_WRITE (allows write access).
    pub fn unprotect(&self) -> Result<(), PageError> {
        #[cfg(not(miri))]
        {
            // SAFETY: the address and the length are the mapping's own, so the
            // range is one this process owns.
            let failed =
                unsafe { libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_WRITE) } != 0;

            if failed {
                return Err(PageError::Unprotect);
            }
        }

        self.is_protected.store(false, Ordering::Release);

        Ok(())
    }

    /// Returns a slice view of the page. Caller must ensure page is unprotected.
    ///
    /// # Safety
    /// Page must be unprotected (PROT_READ or PROT_WRITE), otherwise SIGSEGV.
    pub unsafe fn as_slice(&self) -> &[u8] {
        // SAFETY: the address and the length are the mapping's own, and every
        // byte of it is initialized — `new` zeroes the whole page before
        // handing one out. That the page is readable is what this function's
        // own contract asks of the caller.
        unsafe { core::slice::from_raw_parts(self.ptr, self.capacity) }
    }

    /// Returns a mutable slice view of the page. Caller must ensure page is unprotected.
    ///
    /// # Safety
    /// Page must be unprotected (PROT_WRITE), otherwise SIGSEGV.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the address and the length are the mapping's own, every byte
        // of it is initialized by `new`, and `&mut self` is what makes this the
        // only reference to it. That the page is writable is what this
        // function's own contract asks of the caller.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.capacity) }
    }

    /// Zeroizes the page contents. Page must be unprotected.
    ///
    /// # Safety
    /// Page must be unprotected (PROT_WRITE), otherwise SIGSEGV.
    pub unsafe fn zeroize(&mut self) {
        // SAFETY: what `as_mut_slice` asks is that the page be writable, which
        // is what this function's own contract asks of the caller.
        unsafe { self.as_mut_slice().fast_zeroize() };
    }

    /// Unlocks page (allows swapping). Called in Drop.
    pub fn munlock(&self) {
        // SAFETY: the address and the length are the mapping's own. Unlocking
        // one that was never locked is not an error, so this needs no caller to
        // have locked it.
        #[cfg(not(miri))]
        unsafe {
            libc::munlock(self.ptr as *const _, self.capacity)
        };
    }

    pub fn dispose(&mut self) {
        // Best effort: try to unprotect and zeroize before unmapping
        // If unprotect fails, page stays protected (safe)
        if self.is_protected.load(Ordering::Acquire) {
            let _ = self.unprotect();
        }

        // If we can write, zeroize
        if !self.is_protected.load(Ordering::Acquire) {
            // SAFETY: what `zeroize` asks is that the page be writable, and the
            // branch above is only entered where nothing has protected it.
            unsafe { self.zeroize() };
        }

        self.munlock();
        self.munmap();
    }

    /// Unmaps the page. Called in Drop.
    fn munmap(&self) {
        // SAFETY: the address and the length are the ones `mmap` gave back,
        // which is the pair `munmap` takes.
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.capacity) };
    }
}
