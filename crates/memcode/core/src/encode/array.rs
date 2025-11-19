// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::error::MemEncodeError;
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

impl<T, const N: usize> MemDrainEncode for [T; N]
where
    T: Zeroize,
    MemCodeWord: MemCodeTryTakeFrom<T>,
{
    fn mem_encode_required_capacity(&self) -> usize {
        self.as_slice().mem_encode_required_capacity()
    }

    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), MemEncodeError> {
        self.as_mut_slice().drain_into(buf)
    }
}
