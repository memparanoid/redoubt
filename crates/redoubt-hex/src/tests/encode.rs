// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{HexError, bytes_to_hex};

// ============================================================================
// bytes_to_hex
// ============================================================================

#[test]
fn test_bytes_to_hex_reports_a_destination_too_short() {
    let mut digits = [0xA5_u8; 3];

    assert_eq!(
        bytes_to_hex(&[0x9E, 0x41], &mut digits),
        Err(HexError::WrongDestination)
    );
    assert_eq!(digits, [0xA5; 3], "wrote into a destination it refused");
}

#[test]
fn test_bytes_to_hex_reports_a_destination_too_long() {
    let mut digits = [0xA5_u8; 5];

    assert_eq!(
        bytes_to_hex(&[0x9E, 0x41], &mut digits),
        Err(HexError::WrongDestination)
    );
    assert_eq!(digits, [0xA5; 5], "wrote into a destination it refused");
}

#[test]
fn test_bytes_to_hex_writes_lowercase_digits() {
    let mut digits = [0_u8; 8];

    assert_eq!(bytes_to_hex(&[0x9E, 0x41, 0x0A, 0xFF], &mut digits), Ok(()));
    assert_eq!(&digits, b"9e410aff");
}
