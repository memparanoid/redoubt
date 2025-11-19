// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::error::MemEncodeError;
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

use super::common::{slice_drain_into, slice_required_capacity};

impl<T> MemDrainEncode for [T]
where
    T: Zeroize,
    MemCodeWord: MemCodeTryTakeFrom<T>,
{
    fn mem_encode_required_capacity(&self) -> usize {
        slice_required_capacity(self)
    }

    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), MemEncodeError> {
        slice_drain_into(self, buf)
    }
}
