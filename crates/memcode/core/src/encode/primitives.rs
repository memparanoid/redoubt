// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroizing;

use crate::error::MemEncodeError;
use crate::take::try_take_into;
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

/// Encode impls
macro_rules! impl_mem_drain_encode_for_prims {
    ($($ty:ty),* $(,)?) => {
        $(
            impl MemDrainEncode for $ty {
                #[inline(always)]
                fn mem_encode_required_capacity(&self) -> usize {
                    let header_len = 1;
                    let primitive_len = 1;

                    header_len + primitive_len
                }

                #[inline(always)]
                fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), MemEncodeError> {
                    let coerced = Zeroizing::new(try_take_into::<$ty, MemCodeWord>(self)?);
                    let header_len = 1;

                    buf.push(header_len)?;
                    buf.push(*coerced)?;

                    Ok(())
                }
            }
        )*
    };
}

impl_mem_drain_encode_for_prims!(u8, u16, u32, u64, usize);

impl MemDrainEncode for bool {
    fn mem_encode_required_capacity(&self) -> usize {
        let header_len = 1;
        let primitive_len = 1;
        header_len + primitive_len
    }

    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), MemEncodeError> {
        let coerced = Zeroizing::new(try_take_into::<bool, MemCodeWord>(self)?);
        let header_len = 1;

        buf.push(header_len)?;
        buf.push(*coerced)?;

        Ok(())
    }
}
