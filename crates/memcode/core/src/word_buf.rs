// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::codec::{calculate_len_for_bytes, try_take_words_from_bytes_and_zeroize};
use crate::error::WordBufError;
use crate::traits::DefaultValue;
use crate::types::MemCodeWord;

#[cfg_attr(test, derive(Debug))]
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct WordBuf {
    buf: Vec<MemCodeWord>,
    cursor: usize,
}

impl WordBuf {
    pub fn new(capacity: usize) -> Self {
        let buf = Vec::new();

        let mut word_buf = Self { buf, cursor: 0 };
        word_buf.reset_with_capacity(capacity);

        word_buf
    }

    pub fn reset_with_capacity(&mut self, capacity: usize) {
        self.buf.zeroize();

        let mut buf = Vec::with_capacity(capacity);
        buf.resize_with(capacity, MemCodeWord::default_zero_value);

        self.cursor = 0;
        self.buf = buf;
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.cursor
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn as_slice(&self) -> &[MemCodeWord] {
        &self.buf
    }

    pub fn as_mut_slice(&mut self) -> &mut [MemCodeWord] {
        &mut self.buf
    }

    pub fn push(&mut self, word: MemCodeWord) -> Result<(), WordBufError> {
        if self.cursor >= self.buf.len() {
            return Err(WordBufError::CapacityExceededError);
        }

        self.buf[self.cursor] = word;
        self.cursor += 1;

        Ok(())
    }

    pub fn try_from_bytes(&mut self, bytes: &mut [u8]) -> Result<(), WordBufError> {
        let mut words = try_take_words_from_bytes_and_zeroize(bytes)?;

        self.reset_with_capacity(words.len());

        for word in words.iter_mut() {
            self.push(core::mem::take(word))
                .expect("Infallible: WordBuf has already been reserved with enough space");
        }

        Ok(())
    }

    pub fn calculate_len_for_bytes(&self) -> usize {
        calculate_len_for_bytes(self.cursor)
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let len = self.len();
        let needed = len * core::mem::size_of::<MemCodeWord>();

        let mut dst = Vec::with_capacity(needed);
        dst.resize_with(needed, || 0);

        let mut write_idx = 0;

        for i in 0..len {
            let w = core::mem::take(&mut self.buf[i]);
            let mut bytes = w.to_le_bytes();

            dst[write_idx..write_idx + 4].copy_from_slice(&bytes);
            write_idx += 4;

            bytes.zeroize();
        }

        dst
    }
}
