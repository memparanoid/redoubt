// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{HexError, hex_to_bytes};

// ============================================================================
// hex_to_bytes
// ============================================================================

#[test]
fn test_hex_to_bytes_reports_an_odd_length() {
    let mut bytes = [0xA5_u8; 1];

    assert_eq!(hex_to_bytes(b"9e4", &mut bytes), Err(HexError::OddLength));
    assert_eq!(bytes, [0xA5], "wrote into a destination it refused");
}

#[test]
fn test_hex_to_bytes_reports_a_destination_too_short() {
    let mut bytes = [0xA5_u8; 1];

    assert_eq!(
        hex_to_bytes(b"9e41", &mut bytes),
        Err(HexError::WrongDestination)
    );
    assert_eq!(bytes, [0xA5], "wrote into a destination it refused");
}

#[test]
fn test_hex_to_bytes_reports_a_destination_too_long() {
    let mut bytes = [0xA5_u8; 3];

    assert_eq!(
        hex_to_bytes(b"9e41", &mut bytes),
        Err(HexError::WrongDestination)
    );
    assert_eq!(bytes, [0xA5; 3], "wrote into a destination it refused");
}

#[test]
fn test_hex_to_bytes_reports_a_character_that_is_not_a_digit_and_leaves_zeros() {
    let mut bytes = [0xA5_u8; 2];

    assert_eq!(hex_to_bytes(b"9e4g", &mut bytes), Err(HexError::NotHex));
    assert_eq!(bytes, [0; 2]);
}

#[test]
fn test_hex_to_bytes_reads_both_cases() {
    let mut bytes = [0_u8; 4];

    assert_eq!(hex_to_bytes(b"9E41aFfA", &mut bytes), Ok(()));
    assert_eq!(bytes, [0x9E, 0x41, 0xAF, 0xFA]);
}
