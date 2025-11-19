// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::traits::DefaultValue;

pub type MemCodeWord = u32;
pub type MemCodeUnit = u8;
// It's crucial to guarantee in compilation time
// that MemCodeUnit::MAX < MemCodeWord::MAX
// so that coerce_value<MemCodeUnit, MemCodeWord> is infallible.
// DO NOT REMOVE THE NEXT LINE
const _: [(); 1] = [(); (MemCodeWord::MAX as usize > MemCodeUnit::MAX as usize) as usize];

impl DefaultValue<MemCodeWord> for MemCodeWord {
    fn cast(v: usize) -> MemCodeWord {
        v as MemCodeWord
    }

    fn default_zero_value() -> MemCodeWord {
        0
    }
}

impl DefaultValue<MemCodeUnit> for MemCodeUnit {
    fn cast(v: usize) -> MemCodeUnit {
        v as MemCodeUnit
    }

    fn default_zero_value() -> MemCodeUnit {
        0
    }
}
