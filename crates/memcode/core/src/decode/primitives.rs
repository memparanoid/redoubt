// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::{Zeroize, Zeroizing};

use crate::error::MemDecodeError;
use crate::take::try_take_into;
use crate::traits::{MemDecodeValidateInvariant, MemDrainDecode, TryMemDrainDecode};
use crate::types::*;

/// Implements `MemDecodeValidateInvariant` + `MemDrainDecode` for primitive numeric types.
macro_rules! impl_mem_drain_decode_for_prims {
    ($($ty:ty),* $(,)?) => {
        $(
            impl TryMemDrainDecode for $ty {
                #[inline(always)]
                fn try_drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
                    self.mem_decode_validate_invariant(words)?;
                    *self = try_take_into::<MemCodeWord, $ty>(&mut words[1])?;
                    Ok(())
                }
            }

            impl MemDecodeValidateInvariant for $ty {
                #[inline(always)]
                fn mem_decode_validate_invariant(&self, words: &[MemCodeWord]) -> Result<(), MemDecodeError> {
                    if words.len() != 2 {
                        return Err(MemDecodeError::PreconditionsViolatedError);
                    }

                    Ok(())
                }
            }

            impl MemDrainDecode for $ty {
                #[inline(always)]
                fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
                    let result = self.try_drain_from(words);

                    words.zeroize();

                    if result.is_err() {
                        self.zeroize();
                    }

                    result
                }
            }
        )*
    };
}

impl_mem_drain_decode_for_prims!(u8, u16, u32, u64, usize);

impl MemDecodeValidateInvariant for bool {
    fn mem_decode_validate_invariant(&self, words: &[MemCodeWord]) -> Result<(), MemDecodeError> {
        if words.len() != 2 {
            return Err(MemDecodeError::PreconditionsViolatedError);
        }

        Ok(())
    }
}

impl TryMemDrainDecode for bool {
    fn try_drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        self.mem_decode_validate_invariant(words)?;

        let word = Zeroizing::new(core::mem::take(&mut words[1]));

        words.zeroize();

        *self = *word > 0;

        Ok(())
    }
}

impl MemDrainDecode for bool {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let result = self.try_drain_from(words);

        if result.is_err() {
            self.zeroize();
        }

        result
    }
}
