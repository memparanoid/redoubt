// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{MemBytesRequired, MemDecode, MemEncode};
use proptest::prelude::*;

proptest! {
    #[test]
    fn roundtrip_depth_1_variable_quantity(
        quantity in 1..=100usize
    ) {
        let mut original: Vec<u8> = (1..=quantity).map(|i| i as u8).collect();

        let mut buf = MemEncodeBuf::new(
            original
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()"),
        );

        // Assert (not) zeroization!
        prop_assert!(original.iter().any(|b| *b != 0));

        original
            .drain_into(&mut buf)
            .expect("Failed to drain_into(..)");

        let mut recovered: Vec<u8> = Vec::new();
        let consumed = recovered
            .drain_from(buf.as_mut_slice())
            .expect("Failed to drain_from(..)");

        // Assert zeroization!
        prop_assert!(original.iter().all(|b| *b == 0));
        prop_assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
    }

    #[test]
    fn roundtrip_depth_2_variable_quantities(
        outer_quantity in 1..=10usize,
        inner_quantity in 1..=20usize
    ) {
        let mut original: Vec<Vec<u8>> = (0..outer_quantity)
            .map(|_| (1..=inner_quantity).map(|i| i as u8).collect())
            .collect();

        let mut buf = MemEncodeBuf::new(
            original
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()"),
        );

        // Assert (not) zeroization!
        prop_assert!(original.iter().any(|v| v.iter().any(|b| *b != 0)));

        original
            .drain_into(&mut buf)
            .expect("Failed to drain_into(..)");

        let mut recovered: Vec<Vec<u8>> = Vec::new();
        let consumed = recovered
            .drain_from(buf.as_mut_slice())
            .expect("Failed to drain_from(..)");

        // Assert zeroization!
        prop_assert!(original.iter().all(|v| v.iter().all(|b| *b == 0)));
        prop_assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
    }

    #[test]
    fn roundtrip_depth_3_variable_quantities(
        outer_quantity in 1..=5usize,
        middle_quantity in 1..=5usize,
        inner_quantity in 1..=10usize
    ) {
        let mut original: Vec<Vec<Vec<u8>>> = (0..outer_quantity)
            .map(|_| {
                (0..middle_quantity)
                    .map(|_| (1..=inner_quantity).map(|i| i as u8).collect())
                    .collect()
            })
            .collect();

        let mut buf = MemEncodeBuf::new(
            original
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()"),
        );

        // Assert (not) zeroization!
        prop_assert!(original.iter().any(|v1| v1.iter().any(|v2| v2.iter().any(|b| *b != 0))));

        original
            .drain_into(&mut buf)
            .expect("Failed to drain_into(..)");

        let mut recovered: Vec<Vec<Vec<u8>>> = Vec::new();
        let consumed = recovered
            .drain_from(buf.as_mut_slice())
            .expect("Failed to drain_from(..)");

        // Assert zeroization!
        prop_assert!(original.iter().all(|v1| v1.iter().all(|v2| v2.iter().all(|b| *b == 0))));
        prop_assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
    }

    #[test]
    fn roundtrip_depth_4_variable_quantities(
        q1 in 1..=3usize,
        q2 in 1..=3usize,
        q3 in 1..=3usize,
        q4 in 1..=10usize
    ) {
        let mut original: Vec<Vec<Vec<Vec<u8>>>> = (0..q1)
            .map(|_| {
                (0..q2)
                    .map(|_| {
                        (0..q3)
                            .map(|_| (1..=q4).map(|i| i as u8).collect())
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let mut buf = MemEncodeBuf::new(
            original
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()"),
        );

        // Assert (not) zeroization!
        prop_assert!(original.iter().any(|v1| v1.iter().any(|v2| v2.iter().any(|v3| v3.iter().any(|b| *b != 0)))));

        original
            .drain_into(&mut buf)
            .expect("Failed to drain_into(..)");

        let mut recovered: Vec<Vec<Vec<Vec<u8>>>> = Vec::new();
        let consumed = recovered
            .drain_from(buf.as_mut_slice())
            .expect("Failed to drain_from(..)");

        // Assert zeroization!
        prop_assert!(original.iter().all(|v1| v1.iter().all(|v2| v2.iter().all(|v3| v3.iter().all(|b| *b == 0)))));
        prop_assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
    }

    #[test]
    fn roundtrip_depth_5_variable_quantities(
        q1 in 1..=2usize,
        q2 in 1..=2usize,
        q3 in 1..=2usize,
        q4 in 1..=2usize,
        q5 in 1..=10usize
    ) {
        let mut original: Vec<Vec<Vec<Vec<Vec<u8>>>>> = (0..q1)
            .map(|_| {
                (0..q2)
                    .map(|_| {
                        (0..q3)
                            .map(|_| {
                                (0..q4)
                                    .map(|_| (1..=q5).map(|i| i as u8).collect())
                                    .collect()
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let mut buf = MemEncodeBuf::new(
            original
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()"),
        );

        // Assert (not) zeroization!
        prop_assert!(original.iter().any(|v1| v1.iter().any(|v2| v2.iter().any(|v3| v3.iter().any(|v4| v4.iter().any(|b| *b != 0))))));

        original
            .drain_into(&mut buf)
            .expect("Failed to drain_into(..)");

        let mut recovered: Vec<Vec<Vec<Vec<Vec<u8>>>>> = Vec::new();
        let consumed = recovered
            .drain_from(buf.as_mut_slice())
            .expect("Failed to drain_from(..)");

        // Assert zeroization!
        prop_assert!(original.iter().all(|v1| v1.iter().all(|v2| v2.iter().all(|v3| v3.iter().all(|v4| v4.iter().all(|b| *b == 0))))));
        prop_assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
    }
}
