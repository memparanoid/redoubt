// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! PageBuffer - High-level buffer over a protected Page.
//!
//! Provides open/open_mut access pattern with automatic protect/unprotect.
//! On protection errors, the page is disposed and the process aborts.


use crate::error::{BufferError, PageError};
use crate::page::Page;
use crate::traits::Buffer;

/// Memory protection strategy for the buffer.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProtectionStrategy {
    /// mlock + mprotect toggling (full protection)
    MemProtected,
    /// mlock only (no mprotect toggling)
    MemNonProtected,
}

/// A buffer backed by a memory-locked page with optional memory protection.
pub struct PageBuffer {
    page: Page,
    len: usize,
    strategy: ProtectionStrategy,
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

    /// Creates a new PageBuffer with the specified protection strategy and length.
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
        })
    }

    fn maybe_unprotect(&mut self) -> Result<(), PageError> {
        if self.strategy == ProtectionStrategy::MemProtected {
            self.page.unprotect()?;
        }

        Ok(())
    }

    fn maybe_protect(&mut self) -> Result<(), PageError> {
        if self.strategy == ProtectionStrategy::MemProtected {
            self.page.protect()?;
        }

        Ok(())
    }

    fn try_open(
        &mut self,
        f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError> {
        self.maybe_unprotect()?;

        let slice = unsafe { self.page.as_slice() };
        f(&slice[..self.len])?;

        self.maybe_protect()?;

        Ok(())
    }

    fn try_open_mut(
        &mut self,
        f: &mut dyn FnMut(&mut [u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError> {
        self.maybe_unprotect()?;

        let slice = unsafe { self.page.as_mut_slice() };
        f(&mut slice[..self.len])?;

        self.maybe_protect()?;

        Ok(())
    }

    /// Returns true if the buffer has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Disposes of the underlying page, releasing all resources.
    pub fn dispose(&mut self) {
        self.page.dispose();
    }
}

// Safety: PageBuffer can be shared between threads (though mutation requires &mut)
unsafe impl Sync for PageBuffer {}

impl core::fmt::Debug for PageBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageBuffer")
            .field("len", &self.len)
            .field("strategy", &self.strategy)
            .finish_non_exhaustive()
    }
}

impl Buffer for PageBuffer {
    #[inline(always)]
    fn open(&mut self, f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>) -> Result<(), BufferError> {
        let result = self.try_open(f);

        if let Err(BufferError::Page(e)) = &result {
            self.page.dispose();
            Self::abort(*e);
        }

        result
    }

    #[inline(always)]
    fn open_mut(
        &mut self,
        f: &mut dyn FnMut(&mut [u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError> {
        let result = self.try_open_mut(f);

        if let Err(BufferError::Page(e)) = &result {
            self.page.dispose();
            Self::abort(*e);
        }

        result
    }

    fn len(&self) -> usize {
        self.len
    }
}
