// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use insta::assert_snapshot;
use zeroize::Zeroize;

use crate::MemEncodeError;
use crate::WordBufError;
use crate::error::MemDecodeError;
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

use crate::utils::non_primitive::{drain_from, drain_into, mem_encode_required_capacity};

#[derive(Debug, Eq, PartialEq, Zeroize)]
struct Very {
    pub nested: Nested,
    pub data: [MemCodeUnit; 64],
}

impl Default for Very {
    fn default() -> Self {
        Self {
            data: [MemCodeUnit::MAX; 64],
            nested: Nested::default(),
        }
    }
}

impl MemDrainEncode for Very {
    fn mem_encode_required_capacity(&self) -> usize {
        let fields: [&dyn MemDrainEncode; 2] = [&self.nested, &self.data];
        mem_encode_required_capacity(&fields)
    }

    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), crate::error::MemEncodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainEncode; 2] = [&mut self.nested, &mut self.data];
        drain_into(&mut fields, buf)
    }
}

impl MemDrainDecode for Very {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainDecode; 2] = [&mut self.nested, &mut self.data];
        drain_from(&mut fields, words)
    }
}

#[derive(Debug, Eq, PartialEq, Zeroize)]
struct Nested {
    pub deep: Deep,
    pub data: [MemCodeUnit; 64],
}

impl Default for Nested {
    fn default() -> Self {
        Self {
            data: [MemCodeUnit::MAX; 64],
            deep: Deep::default(),
        }
    }
}

impl MemDrainEncode for Nested {
    fn mem_encode_required_capacity(&self) -> usize {
        let fields: [&dyn MemDrainEncode; 2] = [&self.deep, &self.data];
        mem_encode_required_capacity(&fields)
    }

    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), crate::error::MemEncodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainEncode; 2] = [&mut self.deep, &mut self.data];
        drain_into(&mut fields, buf)
    }
}

impl MemDrainDecode for Nested {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainDecode; 2] = [&mut self.deep, &mut self.data];
        drain_from(&mut fields, words)
    }
}

#[derive(Debug, Eq, PartialEq, Zeroize)]
struct Deep {
    pub structure: Structure,
    pub data: [MemCodeUnit; 64],
}

impl Default for Deep {
    fn default() -> Self {
        Self {
            data: [MemCodeUnit::MAX; 64],
            structure: Structure::default(),
        }
    }
}

impl MemDrainEncode for Deep {
    fn mem_encode_required_capacity(&self) -> usize {
        let fields: [&dyn MemDrainEncode; 2] = [&self.structure, &self.data];
        mem_encode_required_capacity(&fields)
    }

    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), crate::error::MemEncodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainEncode; 2] =
            [&mut self.structure, &mut self.data];
        drain_into(&mut fields, buf)
    }
}

impl MemDrainDecode for Deep {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainDecode; 2] =
            [&mut self.structure, &mut self.data];
        drain_from(&mut fields, words)
    }
}

#[derive(Debug, Eq, PartialEq, Zeroize)]
struct Structure {
    pub data: [MemCodeUnit; 64],
}

impl Default for Structure {
    fn default() -> Self {
        Self {
            data: [MemCodeUnit::MAX; 64],
        }
    }
}

impl MemDrainEncode for Structure {
    fn mem_encode_required_capacity(&self) -> usize {
        let fields: [&dyn MemDrainEncode; 1] = [&self.data];
        mem_encode_required_capacity(&fields)
    }

    fn drain_into(&mut self, buf: &mut WordBuf) -> Result<(), crate::error::MemEncodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainEncode; 1] = [&mut self.data];
        drain_into(&mut fields, buf)
    }
}

impl MemDrainDecode for Structure {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let mut fields: [&mut dyn ZeroizableMemDrainDecode; 1] = [&mut self.data];
        drain_from(&mut fields, words)
    }
}

#[test]
fn test_very_nested_deep_structure() {
    let mut very = Very::default();

    let snapshot_1 = format!("{:?}", very);
    assert_snapshot!(snapshot_1);

    let mut wb = WordBuf::new(very.mem_encode_required_capacity());
    let result = very.drain_into(&mut wb);

    assert!(result.is_ok());

    // zeroized snapshot
    let snapshot_2 = format!("{:?}", very);
    assert_snapshot!(snapshot_2);

    let mut bytes = wb.to_bytes();

    // Assert zeroization!
    assert!(wb.as_slice().iter().all(|b| *b == 0));

    let snapshot_3 = format!("{:?}", bytes);
    assert_snapshot!(snapshot_3);

    let mut recovered_wb = WordBuf::new(0);
    recovered_wb
        .try_from_bytes(&mut bytes)
        .expect("Failed try_from_bytes");
    // Assert zeroization
    assert!(bytes.iter().all(|b| *b == 0));

    let result = very.drain_from(recovered_wb.as_mut_slice());
    assert!(result.is_ok());

    let snapshot_4 = format!("{:?}", very);
    assert_eq!(snapshot_4, snapshot_1);

    // Assert zeroization!
    assert!(recovered_wb.as_slice().iter().all(|b| *b == 0));
}

#[test]
fn test_very_nested_deep_structure_is_zeroized_on_failure() {
    let mut very = Very::default();

    // Not zeroized
    let snapshot_1 = format!("{:?}", very);
    assert_snapshot!(snapshot_1);

    // drain_from it's expected to fail due to insufficient capacity
    let short_required_capacity = very.mem_encode_required_capacity() - 1;
    let mut wb = WordBuf::new(short_required_capacity);

    let result = very.drain_into(&mut wb);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::WordBufError(
            WordBufError::CapacityExceededError
        ))
    ));

    // zeroized
    let snapshot_2 = format!("{:?}", very);
    assert_snapshot!(snapshot_2);

    // Assert zeroization!
    assert!(wb.as_slice().iter().all(|b| *b == 0));
}
