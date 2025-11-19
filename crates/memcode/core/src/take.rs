// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::any::type_name;

use zeroize::Zeroize;

use super::error::CoerceError;
use super::traits::MemCodeTryTakeFrom;
use super::types::MemCodeWord;
use super::zeroizing_utils::zeroize_mut_slice;

macro_rules! impl_ty_for_mem_word {
    ($($ty:ty),* $(,)?) => {$(
        impl MemCodeTryTakeFrom<$ty> for MemCodeWord {
            #[inline(always)]
            fn try_take_from(value: &mut $ty) -> Result<Self, CoerceError> {
                if *value > MemCodeWord::MAX as $ty {
                    let err = CoerceError::OutOfRange {
                        value: *value as u128,
                        min: 0,
                        max: MemCodeWord::MAX as u128,
                        src: type_name::<$ty>(),
                        dst: type_name::<MemCodeWord>(),
                    };
                    *value = 0 as $ty;
                    Err(err)
                } else {
                    let out = *value as MemCodeWord;
                    *value = 0 as $ty;
                    Ok(out)
                }
            }
        }
    )*};
}

macro_rules! impl_memcode_word_for_ty {
    ($($ty:ty),* $(,)?) => {$(
        impl MemCodeTryTakeFrom<MemCodeWord> for $ty {
            #[inline(always)]
            fn try_take_from(value: &mut MemCodeWord) -> Result<Self, CoerceError> {
                if *value > (<$ty>::MAX as MemCodeWord) {
                    let err = CoerceError::OutOfRange {
                        value: *value as u128,
                        min: 0,
                        max: <$ty>::MAX as u128,
                        src: type_name::<MemCodeWord>(),
                        dst: type_name::<$ty>(),
                    };
                    *value = 0;
                    Err(err)
                } else {
                    let out = *value as $ty;
                    *value = 0;
                    Ok(out)
                }
            }
        }
    )*};
}

impl_ty_for_mem_word!(u8, u16, u32, u64, usize);
impl_memcode_word_for_ty!(u8, u16, u64, usize);

impl MemCodeTryTakeFrom<bool> for MemCodeWord {
    fn try_take_from(value: &mut bool) -> Result<Self, CoerceError> {
        if *value {
            *value = false;
            return Ok(1);
        }

        Ok(0)
    }
}

impl MemCodeTryTakeFrom<MemCodeWord> for bool {
    fn try_take_from(value: &mut MemCodeWord) -> Result<Self, CoerceError> {
        if *value > 0 {
            *value = 0;
            return Ok(true);
        }

        Ok(false)
    }
}

pub(crate) fn try_try_take_slice_and_zeroize_src<S, T>(
    src: &mut [S],
    out: &mut [T],
) -> Result<(), CoerceError>
where
    S: Default,
    T: Zeroize + MemCodeTryTakeFrom<S>,
{
    if src.len() != out.len() {
        return Err(CoerceError::LengthMismatchError);
    }

    for (i, elem) in src.iter_mut().enumerate() {
        let mut src_mem_code_word = core::mem::take(elem);
        let t = try_take_into::<S, T>(&mut src_mem_code_word)?;
        out[i] = t;
    }

    Ok(())
}

pub(crate) fn try_take_slice_and_zeroize_src<S, T>(
    src: &mut [S],
    out: &mut [T],
) -> Result<(), CoerceError>
where
    S: Zeroize + Default,
    T: Zeroize + MemCodeTryTakeFrom<S>,
{
    let result = try_try_take_slice_and_zeroize_src(src, out);

    zeroize_mut_slice(src);

    if result.is_err() {
        zeroize_mut_slice(out);
    }

    result
}

pub fn try_take_into<S, T>(value: &mut S) -> Result<T, CoerceError>
where
    T: MemCodeTryTakeFrom<S>,
{
    T::try_take_from(value)
}
