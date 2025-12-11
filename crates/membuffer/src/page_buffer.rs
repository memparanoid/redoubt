// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! PageBuffer - High-level buffer over a protected Page.
//!
//! Provides open/open_mut access pattern with automatic protect/unprotect.
//! On protection errors, the page is disposed and the process aborts.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::error::PageError;
use crate::page::Page;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProtectionStrategy {
    /// mlock + mprotect toggling (full protection)
    MemProtected,
    /// mlock only (no mprotect toggling)
    MemNonProtected,
}

pub struct PageBuffer {
    page: Page,
    len: usize,
    strategy: ProtectionStrategy,
    locked: AtomicBool,
}

impl PageBuffer {
    fn abort(error: PageError) -> ! {
        // Use libc::_exit to avoid any cleanup that might need blocked syscalls
        #[cfg(test)]
        std::process::exit(error as i32);

        #[cfg(not(test))]
        {
            let _ = error;
            unsafe { libc::abort() }
        }
    }

    pub fn new(strategy: ProtectionStrategy, len: usize) -> Result<Self, PageError> {
        let page = Page::new()?;

        page.lock()?;

        if strategy == ProtectionStrategy::MemProtected {
            page.protect()?;
        }

        Ok(Self {
            page,
            len,
            strategy,
            locked: AtomicBool::new(false),
        })
    }

    fn maybe_unprotect(&self) -> Result<(), PageError> {
        if self.strategy == ProtectionStrategy::MemProtected {
            self.page.unprotect()?;
        }

        Ok(())
    }

    fn maybe_protect(&self) -> Result<(), PageError> {
        if self.strategy == ProtectionStrategy::MemProtected {
            self.page.protect()?;
        }

        Ok(())
    }

    #[inline(always)]
    pub fn try_open(&self, f: &mut dyn FnMut(&[u8])) -> Result<(), PageError> {
        self.maybe_unprotect()?;

        let slice = unsafe { self.page.as_slice() };
        f(&slice[..self.len]);

        self.maybe_protect()?;

        Ok(())
    }

    #[inline(always)]
    pub fn try_open_mut(&mut self, f: &mut dyn FnMut(&mut [u8])) -> Result<(), PageError> {
        self.maybe_unprotect()?;

        let slice = unsafe { self.page.as_mut_slice() };
        f(&mut slice[..self.len]);

        self.maybe_protect()?;

        Ok(())
    }

    #[inline(always)]
    pub fn open(&self, f: &mut dyn FnMut(&[u8])) {
        self.acquire();

        if let Err(e) = self.try_open(f) {
            self.release();
            self.page.dispose();
            Self::abort(e);
        }

        self.release();
    }

    #[inline(always)]
    pub fn open_mut(&mut self, f: &mut dyn FnMut(&mut [u8])) {
        self.acquire();

        if let Err(e) = self.try_open_mut(f) {
            self.release();
            self.page.dispose();
            Self::abort(e);
        }

        self.release();
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn acquire(&self) {
        while self.locked.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }

    fn release(&self) {
        self.locked.store(false, Ordering::Release);
    }

    pub fn dispose(&mut self) {
        self.page.dispose();
    }
}
