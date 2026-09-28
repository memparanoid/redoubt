// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That the encoding and the decoding hand the backend what it takes: bytes
//! through both come back as they went in.

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::decode::hex_to_bytes_using;
use crate::encode::bytes_to_hex_using;
use crate::{bytes_to_hex, hex_to_bytes};

// ============================================================================
// bytes_to_hex_using and hex_to_bytes_using
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_bytes_come_back_through_a_backend_at_every_length(#[case] backend: Backend) {
    let bytes: Vec<u8> = (0..=u8::MAX).rev().collect();

    for of in 0..=bytes.len() {
        let mut digits = vec![0_u8; 2 * of];
        let mut back = vec![0_u8; of];

        assert_eq!(
            bytes_to_hex_using(backend, &bytes[..of], &mut digits),
            Ok(())
        );
        assert_eq!(hex_to_bytes_using(backend, &digits, &mut back), Ok(()));
        assert_eq!(back, &bytes[..of], "{backend:?}, {of} bytes");
    }
}

// ============================================================================
// bytes_to_hex and hex_to_bytes
// ============================================================================

proptest! {
    #[test]
    fn test_bytes_come_back_as_they_went_in(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut digits = vec![0_u8; 2 * bytes.len()];
        let mut back = vec![0_u8; bytes.len()];

        prop_assert_eq!(bytes_to_hex(&bytes, &mut digits), Ok(()));
        prop_assert_eq!(hex_to_bytes(&digits, &mut back), Ok(()));
        prop_assert_eq!(back, bytes);
    }
}
