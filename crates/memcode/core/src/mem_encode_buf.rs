// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::error::MemEncodeBufError;

#[cfg_attr(test, derive(Debug))]
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MemEncodeBuf {
    buf: Vec<u8>,
    cursor: usize,
}

impl MemEncodeBuf {
    pub fn new(capacity: usize) -> Self {
        let buf = Vec::new();

        let mut buf = Self { buf, cursor: 0 };
        buf.reset_with_capacity(capacity);

        buf
    }

    pub fn reset_with_capacity(&mut self, capacity: usize) {
        self.buf.zeroize();

        let mut buf = Vec::with_capacity(capacity);
        buf.resize_with(capacity, || 0);

        self.cursor = 0;
        self.buf = buf;
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

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

    #[inline(always)]
    pub fn drain_bytes(&mut self, bytes: &mut [u8]) -> Result<(), MemEncodeBufError> {
        let result = self.try_drain_bytes(bytes);

        if result.is_err() {
            bytes.zeroize();
        }

        result
    }

    #[cfg(test)]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn set_cursor_for_test(&mut self, cursor: usize) {
        self.cursor = cursor;
    }
}
