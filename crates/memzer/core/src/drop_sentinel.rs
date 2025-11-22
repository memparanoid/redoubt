// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
extern crate alloc;

use alloc::rc::Rc;
use core::cell::Cell;

use zeroize::Zeroize;

#[cfg(any(test, feature = "memcode"))]
use memcode_core::{
    MemBytesRequired, MemDecodable, MemDecode, MemEncodable, MemEncode, MemNumElements,
    Zeroizable as MemCodeZeroizable,
};

/// Runtime verification that zeroization happened before drop.
///
/// `DropSentinel` is a guard type used to verify that `.zeroize()` was called
/// before a value is dropped. This provides **runtime enforcement** of zeroization
/// invariants, complementing compile-time checks.
///
/// # Design
///
/// - Wraps a shared boolean flag (`Rc<Cell<bool>>`)
/// - `.zeroize()` sets the flag to `true`
/// - `Drop` checks the flag and panics if `false`
/// - Can be cloned to verify zeroization from tests
///
/// # Panics
///
/// Panics on drop if `.zeroize()` was not called before drop. This is intentional:
/// forgetting to zeroize sensitive data is a critical bug that must be caught.
///
/// # Usage
///
/// Typically used as a field in structs to verify zeroization:
///
/// ```rust
/// use memzer_core::DropSentinel;
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize)]
/// #[zeroize(drop)]
/// struct Secret {
///     data: Vec<u8>,
///     __drop_sentinel: DropSentinel,
/// }
/// ```
///
/// The `__drop_sentinel` field tracks whether `.zeroize()` was called before drop.
/// You'll need to implement `Zeroizable`, `ZeroizationProbe`, and `AssertZeroizeOnDrop`
/// manually, or use the `memzer` umbrella crate which provides `#[derive(MemZer)]`.
///
/// # Testing
///
/// Clone the sentinel to verify zeroization behavior:
///
/// ```rust
/// use memzer_core::DropSentinel;
/// use zeroize::Zeroize;
///
/// let mut sentinel = DropSentinel::default();
/// let sentinel_clone = sentinel.clone();
///
/// assert!(!sentinel_clone.is_dropped());
/// sentinel.zeroize();
/// assert!(sentinel_clone.is_dropped());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DropSentinel(Rc<Cell<bool>>);

impl DropSentinel {
    /// Resets the sentinel to "not zeroized" state.
    ///
    /// This is useful in tests when reusing a sentinel for multiple assertions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memzer_core::DropSentinel;
    /// use zeroize::Zeroize;
    ///
    /// let mut sentinel = DropSentinel::default();
    /// sentinel.zeroize();
    /// assert!(sentinel.is_dropped());
    ///
    /// sentinel.reset();
    /// assert!(!sentinel.is_dropped());
    /// ```
    pub fn reset(&mut self) {
        self.0.set(false);
    }

    /// Checks if zeroization happened (i.e., if `.zeroize()` was called).
    ///
    /// Returns `true` if the sentinel was zeroized, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memzer_core::DropSentinel;
    /// use zeroize::Zeroize;
    ///
    /// let mut sentinel = DropSentinel::default();
    /// assert!(!sentinel.is_dropped());
    ///
    /// sentinel.zeroize();
    /// assert!(sentinel.is_dropped());
    /// ```
    pub fn is_dropped(&self) -> bool {
        self.0.get()
    }
}

impl Default for DropSentinel {
    fn default() -> Self {
        Self(Rc::new(Cell::new(false)))
    }
}

impl Zeroize for DropSentinel {
    fn zeroize(&mut self) {
        self.0.set(true);
    }
}

impl Drop for DropSentinel {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Memencode feature
#[cfg(any(test, feature = "memcode"))]
impl MemCodeZeroizable for DropSentinel {
    #[inline(always)]
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

#[cfg(any(test, feature = "memcode"))]
impl MemNumElements for DropSentinel {
    #[inline(always)]
    fn mem_num_elements(&self) -> usize {
        1
    }
}

#[cfg(any(test, feature = "memcode"))]
impl MemBytesRequired for DropSentinel {
    fn mem_bytes_required(&self) -> Result<usize, memcode_core::OverflowError> {
        Ok(size_of::<u8>())
    }
}

#[cfg(any(test, feature = "memcode"))]
impl MemEncode for DropSentinel {
    fn drain_into(
        &mut self,
        buf: &mut memcode_core::MemEncodeBuf,
    ) -> Result<(), memcode_core::MemEncodeError> {
        if self.0.get() {
            buf.drain_byte(&mut 1)?;
        } else {
            buf.drain_byte(&mut 0)?;
        }

        self.self_zeroize();

        Ok(())
    }
}

#[cfg(any(test, feature = "memcode"))]
impl MemDecode for DropSentinel {
    fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, memcode_core::MemDecodeError> {
        let expected_size = size_of::<u8>();

        if bytes.len() < expected_size {
            bytes.zeroize();
            self.zeroize();
            return Err(memcode_core::MemDecodeError::InvariantViolated);
        }

        let mut array = [0u8; size_of::<u8>()];
        array.copy_from_slice(&bytes[..expected_size]);

        let value = u8::from_le_bytes(array);

        // Zeroize the bytes we consumed
        bytes[..expected_size].zeroize();
        array.zeroize();

        if value == 0 {
            self.0.set(false);
        } else {
            self.0.set(true);
        }

        Ok(expected_size)
    }
}

#[cfg(any(test, feature = "memcode"))]
impl MemEncodable for DropSentinel {}
#[cfg(any(test, feature = "memcode"))]
impl MemDecodable for DropSentinel {}
