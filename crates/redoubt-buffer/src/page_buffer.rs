// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! PageBuffer - High-level buffer over a protected Page.
//!
//! Provides open/open_mut access pattern with automatic protect/unprotect.
//! A page that cannot be closed again is emptied and the buffer refuses every
//! later open.

use crate::error::{BufferError, PageError};
use crate::page::Page;
use crate::traits::Buffer;

/// A buffer backed by a memory-locked page, closed to every access between
/// opens.
pub struct PageBuffer {
    pub(crate) page: Page,
    len: usize,
    pub(crate) poisoned: bool,
}

impl PageBuffer {
    /// Creates a new PageBuffer of the specified length, its page locked,
    /// excluded from core dumps, and closed.
    pub fn new(len: usize) -> Result<Self, PageError> {
        let page = Page::new()?;

        page.lock()?;
        page.mark_dontdump()?;
        page.protect()?;

        Ok(Self {
            page,
            len,
            poisoned: false,
        })
    }

    /// Opens the page, or reports that it will not open again.
    pub(crate) fn unseal(&mut self) -> Result<(), BufferError> {
        if self.poisoned {
            return Err(BufferError::PageNoLongerAvailable);
        }

        let Err(error) = self.page.unprotect() else {
            return Ok(());
        };

        // Nothing was read, so the page is still `PROT_NONE` and there is
        // nothing to erase. It is refused from here on because what stops an
        // `mprotect` is a seccomp filter, and a filter cannot be lifted.
        self.poisoned = true;

        Err(error.into())
    }

    /// Closes the page, and empties it where it will not close.
    pub(crate) fn seal(&mut self) -> Result<(), BufferError> {
        let Err(error) = self.page.protect() else {
            return Ok(());
        };

        self.poisoned = true;

        // The failure left the page readable, which is the state this buffer
        // exists to prevent — and the only one in which the contents can still
        // be erased.
        //
        // SAFETY: what `zeroize` asks is that the page be writable, which is
        // what `unseal` left it and what a refused `mprotect` did not change.
        unsafe { self.page.zeroize() };

        Err(error.into())
    }

    /// Returns true if the buffer has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for PageBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageBuffer")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Buffer for PageBuffer {
    #[inline(always)]
    fn open(
        &mut self,
        f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError> {
        self.unseal()?;

        // SAFETY: what `as_slice` asks is that the page be readable, which is
        // what `unseal` left it, and `seal` below closes it again.
        let slice = unsafe { self.page.as_slice() };
        let read = f(&slice[..self.len]);

        // Not a `?` on the callback: a page the error skipped past is a page
        // left readable for the rest of the process.
        self.seal()?;

        read
    }

    #[inline(always)]
    fn open_mut(
        &mut self,
        f: &mut dyn FnMut(&mut [u8]) -> Result<(), BufferError>,
    ) -> Result<(), BufferError> {
        self.unseal()?;

        // SAFETY: what `as_mut_slice` asks is that the page be writable, which
        // is what `unseal` left it, and `&mut self` is what makes this the only
        // reference to it. `seal` below closes it again.
        let slice = unsafe { self.page.as_mut_slice() };
        let written = f(&mut slice[..self.len]);

        // Not a `?` on the callback: a page the error skipped past is a page
        // left writable for the rest of the process.
        self.seal()?;

        written
    }

    fn len(&self) -> usize {
        self.len
    }
}
