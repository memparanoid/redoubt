// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::error::MemDecodeError;
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

use crate::utils::non_primitive::{drain_from, drain_into, mem_encode_required_capacity};

#[derive(Debug, Eq, PartialEq, Zeroize)]
pub struct PlainStructure {
    pub data: [MemCodeUnit; 64],
    pub u8: u8,
    pub u16: u16,
    pub u32: u32,
    pub u64: u64,
    pub usize: usize,
    pub bool: bool,
}

impl PlainStructure {
    pub fn is_zeroized(&self) -> bool {
        return self.data.iter().all(|b| *b == 0)
            && self.u8 == 0
            && self.u16 == 0
            && self.u32 == 0
            && self.u64 == 0
            && self.usize == 0;
    }
}

impl Default for PlainStructure {
    fn default() -> Self {
        Self {
            data: [17; 64],
            u8: 8,
            u16: 16,
            u32: 32,
            u64: 64,
            usize: MemCodeUnit::MAX as usize,
            bool: true,
        }
    }
}

impl MemDrainEncode for PlainStructure {
    fn mem_encode_required_capacity(&self) -> usize {
        let fields: [&dyn MemDrainEncode; 7] = [
            &self.data,
            &self.u8,
            &self.u16,
            &self.u32,
            &self.u64,
            &self.usize,
            &self.bool,
        ];
        mem_encode_required_capacity(&fields)
    }

    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), crate::error::MemEncodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainEncode; 7] = [
            &mut self.data,
            &mut self.u8,
            &mut self.u16,
            &mut self.u32,
            &mut self.u64,
            &mut self.usize,
            &mut self.bool,
        ];
        drain_into(&mut fields, buf)
    }
}

impl MemDrainDecode for PlainStructure {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainDecode; 7] = [
            &mut self.data,
            &mut self.u8,
            &mut self.u16,
            &mut self.u32,
            &mut self.u64,
            &mut self.usize,
            &mut self.bool,
        ];
        drain_from(&mut fields, words)
    }
}

#[test]
fn test_plain_structure() {
    let mut plain_structure = PlainStructure::default();

    assert!(!plain_structure.is_zeroized());

    let mut wb = WordBuf::new(plain_structure.mem_encode_required_capacity());
    let result = plain_structure.drain_into(&mut wb);

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(plain_structure.is_zeroized());

    let mut bytes = wb.to_bytes();

    // Assert zeroization!
    assert!(wb.as_slice().iter().all(|b| *b == 0));

    let mut recovered_wb = WordBuf::new(0);
    recovered_wb
        .try_from_bytes(&mut bytes)
        .expect("Failed to try_from_bytes");

    // Assert zeroization!
    assert!(bytes.as_slice().iter().all(|b| *b == 0));

    let mut plain_structure = PlainStructure::default();
    let expected_plain_structure = PlainStructure::default();

    plain_structure.zeroize();
    assert!(plain_structure.is_zeroized());

    plain_structure
        .drain_from(recovered_wb.as_mut_slice())
        .expect("Failed to decode PlainStructure");

    assert_eq!(plain_structure, expected_plain_structure);

    // Assert zeroization!
    assert!(wb.as_slice().iter().all(|b| *b == 0));
}
