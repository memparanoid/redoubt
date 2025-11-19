// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::coerce::coerce_mem_code_word_into_usize;
use crate::error::MemDecodeError;
use crate::traits::*;
use crate::types::*;

impl MemDrainDecode for Vec<MemCodeUnit> {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let header_len = coerce_mem_code_word_into_usize(&words[0]);

        self.zeroize();
        self.clear();

        self.reserve_exact(header_len);
        self.resize_with(header_len, || 0);

        self.as_mut_slice().drain_from(words)
    }
}
