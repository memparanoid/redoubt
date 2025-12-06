// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ProtectedBuffer - Unix protected memory buffer
//!
//! Uses mmap for allocation, mlock to prevent swapping,
//! and mprotect to control access (best-effort).

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use memzer::{DropSentinel, FastZeroizable, MemZer};

use crate::error::ProtectedBufferError;
use crate::traits::Buffer;
use crate::utils::fill_with_pattern;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProtectionStrategy {
    /// mlock + mprotect (full protection)
    MemProtected,
    /// mlock only (no mprotect toggling)
    MemNonProtected,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub enum TryCreateStage {
    Lock,
    Protect,
    FillWithPattern0,
}

#[derive(MemZer)]
#[cfg_attr(test, derive(Debug))]
pub struct ProtectedBuffer {
    available: AtomicBool,
    ptr: *mut u8,
    len: usize,
    capacity: usize,
    #[memzer(skip)]
    protection_strategy: ProtectionStrategy,
    __drop_sentinel: DropSentinel,
}

// Safety: The buffer owns its memory and controls access
unsafe impl Send for ProtectedBuffer {}
unsafe impl Sync for ProtectedBuffer {}

impl ProtectedBuffer {
    pub(crate) fn try_create_with(
        protection_strategy: ProtectionStrategy,
        len: usize,
        #[allow(unused_variables)] hook: &mut dyn Fn(TryCreateStage, &mut ProtectedBuffer),
    ) -> Result<Self, ProtectedBufferError> {
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
            return Err(ProtectedBufferError::PageCreationFailed);
        }

        let ptr = ptr as *mut u8;
        let mut protected_buffer = Self {
            ptr,
            len,
            capacity,
            protection_strategy,
            available: AtomicBool::new(true),
            __drop_sentinel: DropSentinel::default(),
        };

        #[cfg(test)]
        hook(TryCreateStage::Lock, &mut protected_buffer);
        protected_buffer.lock().map_err(|e| {
            protected_buffer.dispose();
            return e;
        })?;

        #[cfg(test)]
        hook(TryCreateStage::Protect, &mut protected_buffer);
        protected_buffer.protect().map_err(|e| {
            protected_buffer.dispose();
            return e;
        })?;

        #[cfg(test)]
        hook(TryCreateStage::FillWithPattern0, &mut protected_buffer);
        protected_buffer.open_mut(|bytes| {
            fill_with_pattern(bytes, 0u8);
            Ok(())
        })?;

        Ok(protected_buffer)
    }

    pub fn try_create(
        protection_strategy: ProtectionStrategy,
        len: usize,
    ) -> Result<Self, ProtectedBufferError> {
        Self::try_create_with(protection_strategy, len, &mut |_, _| {})
    }

    pub(crate) fn unprotect(&self) -> Result<(), ProtectedBufferError> {
        if self.protection_strategy == ProtectionStrategy::MemProtected {
            let unprotection_failed =
                unsafe { libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_WRITE) } != 0;

            if unprotection_failed {
                return Err(ProtectedBufferError::UnprotectionFailed);
            }
        }

        Ok(())
    }

    pub(crate) fn protect(&self) -> Result<(), ProtectedBufferError> {
        if self.protection_strategy == ProtectionStrategy::MemProtected {
            let protection_failed =
                unsafe { libc::mprotect(self.ptr as *mut _, self.capacity, libc::PROT_NONE) } != 0;

            if protection_failed {
                return Err(ProtectedBufferError::ProtectionFailed);
            }
        }

        Ok(())
    }

    fn lock(&self) -> Result<(), ProtectedBufferError> {
        let mlock_failed = unsafe { libc::mlock(self.ptr as *const _, self.capacity) } != 0;

        if mlock_failed {
            return Err(ProtectedBufferError::LockFailed);
        }

        Ok(())
    }

    pub(crate) fn munmap(&self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.capacity) };
    }

    pub(crate) fn munlock(&self) {
        unsafe {
            libc::munlock(self.ptr as *const _, self.capacity);
        };
    }

    pub(crate) fn zeroize_slice(&self) {
        let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr, self.capacity) };
        slice.fast_zeroize();
    }

    pub(crate) fn dispose(&mut self) {
        if !self.available.load(Ordering::Acquire) {
            return;
        }

        unsafe {
            let can_write = if self.protection_strategy == ProtectionStrategy::MemProtected {
                libc::mprotect(
                    self.ptr as *mut _,
                    self.capacity,
                    libc::PROT_READ | libc::PROT_WRITE,
                ) == 0
            } else {
                true
            };

            // If !can_write: leak the page but keep it locked and protected
            // Catastrophic state, but no sensitive data escapes to swap
            if can_write {
                self.zeroize_slice();
                self.munlock();
                self.munmap();
            }
        }

        self.available.store(false, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn with_self_ptr(&self, f: &mut dyn Fn(*mut u8)) {
        f(self.ptr);
    }
}

impl Buffer for ProtectedBuffer {
    fn open<F>(&mut self, f: F) -> Result<(), ProtectedBufferError>
    where
        F: Fn(&[u8]) -> Result<(), ProtectedBufferError>,
    {
        if !self.available.load(Ordering::Acquire) {
            return Err(ProtectedBufferError::PageNoLongerAvailable);
        }

        self.unprotect()?;

        {
            let slice = unsafe { core::slice::from_raw_parts(self.ptr, self.len) };
            f(slice)?;
        }

        self.protect().map_err(|e| {
            self.dispose();
            self.fast_zeroize();
            e
        })?;

        Ok(())
    }

    fn open_mut<F>(&mut self, f: F) -> Result<(), ProtectedBufferError>
    where
        F: Fn(&mut [u8]) -> Result<(), ProtectedBufferError>,
    {
        if !self.available.load(Ordering::Acquire) {
            return Err(ProtectedBufferError::PageNoLongerAvailable);
        }

        self.unprotect()?;

        {
            let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) };
            f(slice)?;
        }

        self.protect().map_err(|e| {
            self.dispose();
            self.fast_zeroize();
            e
        })?;

        Ok(())
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        self.dispose();
        self.fast_zeroize();
    }
}

#[cfg(test)]
impl Clone for ProtectedBuffer {
    fn clone(&self) -> Self {
        Self {
            available: AtomicBool::new(self.available.load(Ordering::Relaxed)),
            ptr: self.ptr,
            len: self.len,
            capacity: self.capacity,
            protection_strategy: self.protection_strategy.clone(),
            __drop_sentinel: self.__drop_sentinel.clone(),
        }
    }
}
