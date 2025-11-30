// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AES intrinsics tests.

use memutil::hex_to_bytes;

use crate::aegis::intrinsics::Intrinsics;

/// A.1 - AESRound test vector
#[test]
fn test_aes_round() {
    if !std::arch::is_aarch64_feature_detected!("aes") {
        eprintln!("Skipping test: AES not supported");
        return;
    }

    let input = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    let rk = hex_to_bytes("101112131415161718191a1b1c1d1e1f");
    let expected = hex_to_bytes("7a7b4e5638782546a8c0477a3b813f43");

    unsafe {
        let block = Intrinsics::load(input[..].try_into().unwrap());
        let round_key = Intrinsics::load(rk[..].try_into().unwrap());
        let result = block.aes_enc(&round_key);

        let mut out = [0u8; 16];
        result.store(&mut out);
        assert_eq!(out[..], expected[..], "AESRound mismatch");
    }
}
