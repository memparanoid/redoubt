// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::error::MemEncodeError;
use crate::take::try_take_into;
use crate::traits::MemCodeTryTakeFrom;
use crate::types::*;
use crate::word_buf::WordBuf;
use crate::zeroizing_utils::zeroize_mut_slice;

pub fn slice_required_capacity<T>(src: &[T]) -> usize {
    let header_len = 1;
    header_len + src.len()
}

pub fn slice_drain_into<T>(src: &mut [T], buf: &mut WordBuf) -> Result<(), MemEncodeError>
where
    T: Zeroize,
    MemCodeWord: MemCodeTryTakeFrom<T>,
{
    slice_drain_into_with_zeroization(src, buf, &mut coerce_len_into_mem_code_word)
}

// Wrap length→MemCodeWord in a function to make the overflow path testable;
// raw casts aren’t, since arrays > 32 bytes can’t be constructed in this context.
pub(crate) fn slice_drain_into_with<T>(
    src: &mut [T],
    buf: &mut WordBuf,
    f: &mut dyn FnMut(&mut usize) -> Result<MemCodeWord, MemEncodeError>,
) -> Result<(), MemEncodeError>
where
    T: Zeroize,
    MemCodeWord: MemCodeTryTakeFrom<T>,
{
    let len_word = f(&mut src.len())?;

    buf.push(len_word)?;

    for elem in src {
        let coerced = try_take_into::<T, MemCodeWord>(elem)?;
        buf.push(coerced)?;
    }

    Ok(())
}

pub(crate) fn slice_drain_into_with_zeroization<T>(
    src: &mut [T],
    buf: &mut WordBuf,
    f: &mut dyn FnMut(&mut usize) -> Result<MemCodeWord, MemEncodeError>,
) -> Result<(), MemEncodeError>
where
    T: Zeroize,
    MemCodeWord: MemCodeTryTakeFrom<T>,
{
    let result = slice_drain_into_with(src, buf, f);
    zeroize_mut_slice(src);

    if result.is_err() {
        buf.zeroize();
    }

    result
}

pub(crate) fn coerce_len_into_mem_code_word(
    len: &mut usize,
) -> Result<MemCodeWord, MemEncodeError> {
    let word = try_take_into::<usize, MemCodeWord>(len)?;
    Ok(word)
}
