// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::error::MemEncodeBufError;

/// Pre-allocated buffer for encoding data with automatic zeroization.
///
/// `MemEncodeBuf` is a fixed-capacity buffer used for encoding operations. It provides:
/// - **Pre-allocation**: Size is determined upfront via [`MemBytesRequired`](crate::MemBytesRequired)
/// - **Move semantics**: `drain_*` methods consume source data and zeroize it
/// - **Automatic cleanup**: Buffer is zeroized on drop via `#[zeroize(drop)]`
/// - **Error safety**: Zeroization occurs on both success and error paths
///
/// # Design
///
/// - Internal `Vec<u8>` pre-allocated to exact capacity
/// - Cursor tracks write position
/// - All `drain_*` methods zeroize source data after copying
/// - Capacity is fixed after creation (no re-allocations)
///
/// # Example
///
/// ```rust
/// use memcode_core::{MemEncodeBuf, MemBytesRequired, MemEncode};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// let mut value = vec![1u8, 2, 3, 4, 5];
///
/// // Calculate size and pre-allocate buffer
/// let size = value.mem_bytes_required()?;
/// let mut buf = MemEncodeBuf::new(size);
///
/// // Encode (consumes and zeroizes source)
/// value.drain_into(&mut buf)?;
///
/// assert!(value.iter().all(|&b| b == 0)); // Source zeroized
/// assert_eq!(buf.as_slice().len(), size);
/// # Ok(())
/// # }
/// ```
///
/// # Zeroization
///
/// The buffer is automatically zeroized when:
/// - Dropped (via `#[zeroize(drop)]`)
/// - An encoding operation fails
/// - [`reset_with_capacity()`](Self::reset_with_capacity) is called
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MemEncodeBuf {
    buf: Vec<u8>,
    cursor: usize,
}

impl core::fmt::Debug for MemEncodeBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemEncodeBuf")
            .field("len", &self.buf.len())
            .field("cursor", &self.cursor)
            .field("buf", &"[REDACTED]")
            .finish()
    }
}

impl MemEncodeBuf {
    /// Creates a new buffer with the specified capacity.
    ///
    /// The buffer is pre-allocated to exactly `capacity` bytes and filled with zeros.
    /// The cursor starts at position 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::MemEncodeBuf;
    ///
    /// let buf = MemEncodeBuf::new(128);
    /// assert_eq!(buf.len(), 128);
    /// assert!(buf.as_slice().iter().all(|&b| b == 0));
    /// ```
    pub fn new(capacity: usize) -> Self {
        let buf = Vec::new();

        let mut buf = Self { buf, cursor: 0 };
        buf.reset_with_capacity(capacity);

        buf
    }

    /// Resets the buffer with a new capacity, zeroizing previous contents.
    ///
    /// This method:
    /// 1. Zeroizes the existing buffer
    /// 2. Allocates a new buffer with the specified capacity
    /// 3. Fills it with zeros
    /// 4. Resets the cursor to 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::MemEncodeBuf;
    ///
    /// let mut buf = MemEncodeBuf::new(64);
    /// buf.reset_with_capacity(128);
    ///
    /// assert_eq!(buf.len(), 128);
    /// ```
    pub fn reset_with_capacity(&mut self, capacity: usize) {
        self.buf.zeroize();

        let mut buf = Vec::with_capacity(capacity);
        buf.resize_with(capacity, || 0);

        self.cursor = 0;
        self.buf = buf;
    }

    /// Returns the total capacity of the buffer in bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::MemEncodeBuf;
    ///
    /// let buf = MemEncodeBuf::new(256);
    /// assert_eq!(buf.len(), 256);
    /// ```
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer has zero capacity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::MemEncodeBuf;
    ///
    /// let buf = MemEncodeBuf::new(0);
    /// assert!(buf.is_empty());
    ///
    /// let buf = MemEncodeBuf::new(1);
    /// assert!(!buf.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns an immutable slice view of the buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::MemEncodeBuf;
    ///
    /// let buf = MemEncodeBuf::new(10);
    /// let slice = buf.as_slice();
    /// assert_eq!(slice.len(), 10);
    /// ```
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Returns a mutable slice view of the buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::MemEncodeBuf;
    ///
    /// let mut buf = MemEncodeBuf::new(10);
    /// let slice = buf.as_mut_slice();
    /// slice[0] = 42;
    /// assert_eq!(buf.as_slice()[0], 42);
    /// ```
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub(crate) fn try_drain_byte(&mut self, byte: &mut u8) -> Result<(), MemEncodeBufError> {
        if self.cursor >= self.buf.len() {
            return Err(MemEncodeBufError::CapacityExceededError);
        }

        self.buf[self.cursor] = core::mem::take(byte);
        self.cursor += 1;

        Ok(())
    }

    /// Drains a single byte into the buffer, zeroizing the source.
    ///
    /// This method:
    /// 1. Copies the byte to the current cursor position
    /// 2. Zeroizes the source byte
    /// 3. Advances the cursor by 1
    ///
    /// On success, the source byte is zeroized.
    /// On error, both the source byte and the buffer are zeroized.
    ///
    /// # Errors
    ///
    /// Returns [`MemEncodeBufError::CapacityExceededError`] if cursor >= buffer length.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::MemEncodeBuf;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let mut buf = MemEncodeBuf::new(1);
    /// let mut byte = 42u8;
    ///
    /// buf.drain_byte(&mut byte)?;
    ///
    /// assert_eq!(byte, 0); // Source zeroized
    /// assert_eq!(buf.as_slice()[0], 42);
    /// # Ok(())
    /// # }
    /// ```
    pub fn drain_byte(&mut self, byte: &mut u8) -> Result<(), MemEncodeBufError> {
        let result = self.try_drain_byte(byte);

        if result.is_err() {
            byte.zeroize();
            self.zeroize();
        }

        result
    }

    #[inline(always)]
    pub(crate) fn try_drain_bytes(&mut self, bytes: &mut [u8]) -> Result<(), MemEncodeBufError> {
        let end_pos = self
            .cursor
            .checked_add(bytes.len())
            .ok_or(MemEncodeBufError::CapacityExceededError)?;

        if end_pos > self.buf.len() {
            return Err(MemEncodeBufError::CapacityExceededError);
        }

        self.buf[self.cursor..end_pos].copy_from_slice(bytes);

        bytes.zeroize();

        self.cursor = end_pos;
        Ok(())
    }

    /// Drains a byte slice into the buffer, zeroizing the source.
    ///
    /// This method:
    /// 1. Copies all bytes to the buffer starting at the cursor
    /// 2. Zeroizes the source slice
    /// 3. Advances the cursor by `bytes.len()`
    ///
    /// On success, the source bytes are zeroized.
    /// On error, the source bytes are zeroized.
    ///
    /// # Errors
    ///
    /// Returns [`MemEncodeBufError::CapacityExceededError`] if there's insufficient capacity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::MemEncodeBuf;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let mut buf = MemEncodeBuf::new(5);
    /// let mut data = vec![1u8, 2, 3, 4, 5];
    ///
    /// buf.drain_bytes(&mut data)?;
    ///
    /// assert!(data.iter().all(|&b| b == 0)); // Source zeroized
    /// assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
    /// # Ok(())
    /// # }
    /// ```
    #[inline(always)]
    pub fn drain_bytes(&mut self, bytes: &mut [u8]) -> Result<(), MemEncodeBufError> {
        let result = self.try_drain_bytes(bytes);

        if result.is_err() {
            bytes.zeroize();
        }

        result
    }

    /// Returns the current cursor position.
    ///
    /// Only available in test builds.
    #[cfg(test)]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn set_cursor_for_test(&mut self, cursor: usize) {
        self.cursor = cursor;
    }
}
