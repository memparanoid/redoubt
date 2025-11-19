// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::time::Instant;

use zeroize::Zeroize;

use crate::error::MemDecodeError;
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

use crate::utils::non_primitive::{drain_from, drain_into, mem_encode_required_capacity};

use super::super::perm_utils::{apply_permutation_in_place, lehmer_decode_many};

pub trait Combined: ZeroizableMemDrainEncode + ZeroizableMemDrainDecode {
    fn as_mem_drain_encode(&self) -> &dyn MemDrainEncode;
    fn as_zeroizable_mem_drain_decode(&mut self) -> &mut dyn ZeroizableMemDrainDecode;
    fn as_zeroizable_mem_drain_encode(&mut self) -> &mut dyn ZeroizableMemDrainEncode;
}

impl<T: ZeroizableMemDrainEncode + MemDrainDecode + Sized> Combined for T {
    fn as_mem_drain_encode(&self) -> &dyn MemDrainEncode {
        self as &dyn MemDrainEncode
    }

    fn as_zeroizable_mem_drain_encode(&mut self) -> &mut dyn ZeroizableMemDrainEncode {
        self as &mut dyn ZeroizableMemDrainEncode
    }

    fn as_zeroizable_mem_drain_decode(&mut self) -> &mut dyn ZeroizableMemDrainDecode {
        self as &mut dyn ZeroizableMemDrainDecode
    }
}

#[derive(Debug, Eq, PartialEq, Zeroize)]
pub struct PermStruct {
    pub fixed_array_0: [MemCodeUnit; 0],
    pub fixed_array_1: [MemCodeUnit; 1],
    pub fixed_array_2: [MemCodeUnit; 2],
    pub fixed_array_4: [MemCodeUnit; 4],
    pub fixed_array_8: [MemCodeUnit; 8],
    pub fixed_array_16: [MemCodeUnit; 16],
    pub fixed_array_32: [MemCodeUnit; 32],
    pub fixed_array_64: [MemCodeUnit; 64],
    pub fixed_array_128: [MemCodeUnit; 128],
    pub vec_0: Vec<MemCodeUnit>,
    pub vec_1: Vec<MemCodeUnit>,
    pub vec_2: Vec<MemCodeUnit>,
    pub vec_4: Vec<MemCodeUnit>,
    pub vec_8: Vec<MemCodeUnit>,
    pub vec_16: Vec<MemCodeUnit>,
    pub vec_32: Vec<MemCodeUnit>,
    pub vec_64: Vec<MemCodeUnit>,
    pub vec_128: Vec<MemCodeUnit>,
}

impl PermStruct {
    pub fn new() -> Self {
        Self {
            fixed_array_0: [],
            fixed_array_1: [MemCodeUnit::default_zero_value(); 1],
            fixed_array_2: [MemCodeUnit::default_zero_value(); 2],
            fixed_array_4: [MemCodeUnit::default_zero_value(); 4],
            fixed_array_8: [MemCodeUnit::default_zero_value(); 8],
            fixed_array_16: [MemCodeUnit::default_zero_value(); 16],
            fixed_array_32: [MemCodeUnit::default_zero_value(); 32],
            fixed_array_64: [MemCodeUnit::default_zero_value(); 64],
            fixed_array_128: [MemCodeUnit::default_zero_value(); 128],
            vec_0: vec![],
            vec_1: vec![MemCodeUnit::default_zero_value(); 1],
            vec_2: vec![MemCodeUnit::default_zero_value(); 2],
            vec_4: vec![MemCodeUnit::default_zero_value(); 4],
            vec_8: vec![MemCodeUnit::default_zero_value(); 8],
            vec_16: vec![MemCodeUnit::default_zero_value(); 16],
            vec_32: vec![MemCodeUnit::default_zero_value(); 32],
            vec_64: vec![MemCodeUnit::default_zero_value(); 64],
            vec_128: vec![MemCodeUnit::default_zero_value(); 128],
        }
    }

    pub fn fill(&mut self) {
        self.fixed_array_0 = [];
        self.fixed_array_1 = [MemCodeUnit::cast(1); 1];
        self.fixed_array_2 = [MemCodeUnit::cast(2); 2];
        self.fixed_array_4 = [MemCodeUnit::cast(4); 4];
        self.fixed_array_8 = [MemCodeUnit::cast(8); 8];
        self.fixed_array_16 = [MemCodeUnit::cast(16); 16];
        self.fixed_array_32 = [MemCodeUnit::cast(32); 32];
        self.fixed_array_64 = [MemCodeUnit::cast(64); 64];
        self.fixed_array_128 = [MemCodeUnit::cast(128); 128];
        self.vec_0 = vec![];
        self.vec_1 = vec![MemCodeUnit::cast(1); 1];
        self.vec_2 = vec![MemCodeUnit::cast(2); 2];
        self.vec_4 = vec![MemCodeUnit::cast(4); 4];
        self.vec_8 = vec![MemCodeUnit::cast(8); 8];
        self.vec_16 = vec![MemCodeUnit::cast(16); 16];
        self.vec_32 = vec![MemCodeUnit::cast(32); 32];
        self.vec_64 = vec![MemCodeUnit::cast(64); 64];
        self.vec_128 = vec![MemCodeUnit::cast(128); 128];
    }

    fn is_slice_zeroized(slice: &[MemCodeUnit]) -> bool {
        slice.iter().all(|&b| b == 0)
    }

    fn is_slice_filled(slice: &[MemCodeUnit]) -> bool {
        let len = slice.len() as MemCodeUnit;
        slice.iter().all(|&b| b == len)
    }

    fn get_fields_as_slice(&self) -> [&[MemCodeUnit]; 18] {
        let fields: [&[MemCodeUnit]; 18] = [
            self.fixed_array_0.as_slice(),
            self.fixed_array_1.as_slice(),
            self.fixed_array_2.as_slice(),
            self.fixed_array_4.as_slice(),
            self.fixed_array_8.as_slice(),
            self.fixed_array_16.as_slice(),
            self.fixed_array_32.as_slice(),
            self.fixed_array_64.as_slice(),
            self.fixed_array_128.as_slice(),
            self.vec_0.as_slice(),
            self.vec_1.as_slice(),
            self.vec_2.as_slice(),
            self.vec_4.as_slice(),
            self.vec_8.as_slice(),
            self.vec_16.as_slice(),
            self.vec_32.as_slice(),
            self.vec_64.as_slice(),
            self.vec_128.as_slice(),
        ];

        fields
    }

    fn get_fields_as_combined(&self) -> [&dyn Combined; 18] {
        let fields: [&dyn Combined; 18] = [
            &self.fixed_array_0,
            &self.fixed_array_1,
            &self.fixed_array_2,
            &self.fixed_array_4,
            &self.fixed_array_8,
            &self.fixed_array_16,
            &self.fixed_array_32,
            &self.fixed_array_64,
            &self.fixed_array_128,
            &self.vec_0,
            &self.vec_1,
            &self.vec_2,
            &self.vec_4,
            &self.vec_8,
            &self.vec_16,
            &self.vec_32,
            &self.vec_64,
            &self.vec_128,
        ];

        fields
    }

    fn get_mut_fields_as_combined(&mut self) -> [&mut dyn Combined; 18] {
        let fields: [&mut dyn Combined; 18] = [
            &mut self.fixed_array_0,
            &mut self.fixed_array_1,
            &mut self.fixed_array_2,
            &mut self.fixed_array_4,
            &mut self.fixed_array_8,
            &mut self.fixed_array_16,
            &mut self.fixed_array_32,
            &mut self.fixed_array_64,
            &mut self.fixed_array_128,
            &mut self.vec_0,
            &mut self.vec_1,
            &mut self.vec_2,
            &mut self.vec_4,
            &mut self.vec_8,
            &mut self.vec_16,
            &mut self.vec_32,
            &mut self.vec_64,
            &mut self.vec_128,
        ];

        fields
    }

    pub fn is_zeroized(&self) -> bool {
        let fields = self.get_fields_as_slice();
        fields.iter().all(|x| Self::is_slice_zeroized(x))
    }

    pub fn is_filled(&self) -> bool {
        let fields = self.get_fields_as_slice();
        fields.iter().all(|x| Self::is_slice_filled(x))
    }

    pub fn permute<F>(&mut self, number_of_perms: usize, f: F)
    where
        F: Fn(&mut [MemCodeWord]),
    {
        let number_of_fields = 18;
        let required_capacity = self.mem_encode_required_capacity();
        let perms = lehmer_decode_many(number_of_fields, number_of_perms);

        assert_eq!(perms.len(), number_of_perms);

        let start_time = Instant::now();
        for perm in perms {
            self.fill();

            let mut fields = {
                let mut_fields_combined = self.get_mut_fields_as_combined();
                let mut fields_mem_drain_encode: Vec<&mut dyn ZeroizableMemDrainEncode> =
                    mut_fields_combined
                        .into_iter()
                        .map(|x| x.as_zeroizable_mem_drain_encode())
                        .collect();

                apply_permutation_in_place(&mut fields_mem_drain_encode, &perm);

                fields_mem_drain_encode
            };

            let mut wb = WordBuf::new(required_capacity);
            let result = drain_into(&mut fields, &mut wb);

            assert!(result.is_ok());

            f(wb.as_mut_slice());
        }

        let perm_time = start_time.elapsed();
        println!(
            "Time to code/decode {} permutations: {:?}",
            number_of_perms, perm_time
        );
    }
}

impl MemDrainDecode for PermStruct {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        let mut_fields_combined = self.get_mut_fields_as_combined();
        let mut fields_mem_drain_decode: Vec<&mut dyn ZeroizableMemDrainDecode> =
            mut_fields_combined
                .into_iter()
                .map(|x| x.as_zeroizable_mem_drain_decode())
                .collect();

        drain_from(&mut fields_mem_drain_decode, words)
    }
}

impl MemDrainEncode for PermStruct {
    fn mem_encode_required_capacity(&self) -> usize {
        let mut_fields_combined = self.get_fields_as_combined();
        let fields_mem_drain_encode: Vec<&dyn MemDrainEncode> = mut_fields_combined
            .into_iter()
            .map(|x| x.as_mem_drain_encode())
            .collect();

        mem_encode_required_capacity(&fields_mem_drain_encode)
    }

    fn drain_into(&mut self, words: &mut WordBuf) -> Result<(), crate::error::MemEncodeError> {
        let mut_fields_combined = self.get_mut_fields_as_combined();
        let mut fields_mem_drain_encode: Vec<&mut dyn ZeroizableMemDrainEncode> =
            mut_fields_combined
                .into_iter()
                .map(|x| x.as_zeroizable_mem_drain_encode())
                .collect();

        drain_into(&mut fields_mem_drain_encode, words)
    }
}
