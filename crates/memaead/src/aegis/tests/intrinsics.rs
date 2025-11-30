// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for AES intrinsics using RFC test vectors.

use memutil::hex_to_bytes;

use crate::aegis::intrinsics::Intrinsics;

fn hex_to_bytes_16(hex: &str) -> [u8; 16] {
    hex_to_bytes(hex).try_into().unwrap()
}

fn has_aes_support() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
}

/// A.1 AESRound Test Vector from RFC
///
/// in  : 000102030405060708090a0b0c0d0e0f
/// rk  : 101112131415161718191a1b1c1d1e1f
/// out : 7a7b4e5638782546a8c0477a3b813f43
#[test]
fn test_aes_round_rfc_vector() {
    if !has_aes_support() {
        eprintln!("skipping: AES not available");
        return;
    }

    let input = hex_to_bytes_16("000102030405060708090a0b0c0d0e0f");
    let round_key = hex_to_bytes_16("101112131415161718191a1b1c1d1e1f");
    let expected = hex_to_bytes_16("7a7b4e5638782546a8c0477a3b813f43");

    // SAFETY: has_aes_support() verified above
    unsafe {
        let block_in = Intrinsics::load(&input);
        let block_rk = Intrinsics::load(&round_key);
        let result = block_in.aes_enc(&block_rk);

        let mut output = [0u8; 16];
        result.store(&mut output);

        assert_eq!(&output, &expected, "AESRound output mismatch");
    }
}

#[test]
fn test_xor() {
    if !has_aes_support() {
        return;
    }

    let a = hex_to_bytes_16("ffffffffffffffffffffffffffffffff");
    let b = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    let expected = hex_to_bytes_16("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0");

    // SAFETY: has_aes_support() verified above
    unsafe {
        let block_a = Intrinsics::load(&a);
        let block_b = Intrinsics::load(&b);
        let result = block_a.xor(&block_b);

        let mut output = [0u8; 16];
        result.store(&mut output);

        assert_eq!(&output, &expected);
    }
}

#[test]
fn test_and() {
    if !has_aes_support() {
        return;
    }

    let a = hex_to_bytes_16("ffffffffffffffffffffffffffffffff");
    let b = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    let expected = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");

    // SAFETY: has_aes_support() verified above
    unsafe {
        let block_a = Intrinsics::load(&a);
        let block_b = Intrinsics::load(&b);
        let result = block_a.and(&block_b);

        let mut output = [0u8; 16];
        result.store(&mut output);

        assert_eq!(&output, &expected);
    }
}

#[test]
fn test_zero() {
    if !has_aes_support() {
        return;
    }

    // SAFETY: has_aes_support() verified above
    unsafe {
        let zero = Intrinsics::zero();

        let mut output = [0xffu8; 16];
        zero.store(&mut output);

        assert_eq!(&output, &[0u8; 16]);
    }
}
