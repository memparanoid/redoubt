// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::coerce::coerce_mem_code_word_into_usize;
use crate::error::MemDecodeError;
use crate::take::try_take_slice_and_zeroize_src;
use crate::traits::*;
use crate::types::*;
use crate::zeroizing_utils::zeroize_mut_slice;

use super::common::mem_decode_slice_validate_invariant;

#[inline(always)]
fn try_drain_from<T>(src: &mut [T], words: &mut [MemCodeWord]) -> Result<(), MemDecodeError>
where
    T: Zeroize + MemCodeTryTakeFrom<MemCodeWord>,
{
    mem_decode_slice_validate_invariant(src, words)?;

    let header_len = coerce_mem_code_word_into_usize(&words[0]);
    try_take_slice_and_zeroize_src(&mut words[1..header_len + 1], src)?;

    Ok(())
}

impl<T> MemDrainDecode for [T]
where
    T: Zeroize + MemCodeTryTakeFrom<MemCodeWord>,
{
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let result = try_drain_from(self, words);

        words.zeroize();

        if result.is_err() {
            zeroize_mut_slice(self);
        }

        result
    }
}
