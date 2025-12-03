// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for AES intrinsics using RFC test vectors.

use memutil::hex_to_bytes;
use memzer::ZeroizationProbe;
use zeroize::Zeroize;

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

    let mut block_in = Intrinsics::load(&input);
    let mut block_rk = Intrinsics::load(&round_key);
    let mut result = block_in.aes_enc(&block_rk);

    let mut output = [0u8; 16];
    result.store(&mut output);

    assert_eq!(&output, &expected, "AESRound output mismatch");

    // Zeroize before drop
    block_in.zeroize();
    block_rk.zeroize();
    result.zeroize();
}

#[test]
fn test_xor() {
    if !has_aes_support() {
        return;
    }

    let a = hex_to_bytes_16("ffffffffffffffffffffffffffffffff");
    let b = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    let expected = hex_to_bytes_16("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0");

    let mut block_a = Intrinsics::load(&a);
    let mut block_b = Intrinsics::load(&b);
    let mut result = block_a.xor(&block_b);

    let mut output = [0u8; 16];
    result.store(&mut output);

    assert_eq!(&output, &expected);

    // Zeroize before drop
    block_a.zeroize();
    block_b.zeroize();
    result.zeroize();
}

#[test]
fn test_and() {
    if !has_aes_support() {
        return;
    }

    let a = hex_to_bytes_16("ffffffffffffffffffffffffffffffff");
    let b = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    let expected = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");

    let mut block_a = Intrinsics::load(&a);
    let mut block_b = Intrinsics::load(&b);
    let mut result = block_a.and(&block_b);

    let mut output = [0u8; 16];
    result.store(&mut output);

    assert_eq!(&output, &expected);

    // Zeroize before drop
    block_a.zeroize();
    block_b.zeroize();
    result.zeroize();
}

#[test]
fn test_xor_in_place() {
    if !has_aes_support() {
        return;
    }

    let a = hex_to_bytes_16("ffffffffffffffffffffffffffffffff");
    let b = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    let expected = hex_to_bytes_16("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0");

    let mut block_a = Intrinsics::load(&a);
    let mut block_b = Intrinsics::load(&b);

    block_a.xor_in_place(&block_b);

    let mut output = [0u8; 16];
    block_a.store(&mut output);

    assert_eq!(&output, &expected);

    // Zeroize before drop
    block_a.zeroize();
    block_b.zeroize();
}

#[test]
fn test_and_in_place() {
    if !has_aes_support() {
        return;
    }

    let a = hex_to_bytes_16("ffffffffffffffffffffffffffffffff");
    let b = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    let expected = hex_to_bytes_16("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");

    let mut block_a = Intrinsics::load(&a);
    let mut block_b = Intrinsics::load(&b);

    block_a.and_in_place(&block_b);

    let mut output = [0u8; 16];
    block_a.store(&mut output);

    assert_eq!(&output, &expected);

    // Zeroize before drop
    block_a.zeroize();
    block_b.zeroize();
}

#[test]
fn test_aes_enc_in_place() {
    if !has_aes_support() {
        return;
    }

    let input = hex_to_bytes_16("000102030405060708090a0b0c0d0e0f");
    let round_key = hex_to_bytes_16("101112131415161718191a1b1c1d1e1f");
    let expected = hex_to_bytes_16("7a7b4e5638782546a8c0477a3b813f43");

    let mut block = Intrinsics::load(&input);
    let mut rk = Intrinsics::load(&round_key);

    block.aes_enc_in_place(&rk);

    let mut output = [0u8; 16];
    block.store(&mut output);

    assert_eq!(&output, &expected);

    // Zeroize before drop
    block.zeroize();
    rk.zeroize();
}

#[test]
fn test_move_to() {
    if !has_aes_support() {
        return;
    }

    let a = hex_to_bytes_16("000102030405060708090a0b0c0d0e0f");
    let b = hex_to_bytes_16("ffffffffffffffffffffffffffffffff");

    let mut src = Intrinsics::load(&a);
    let mut dst = Intrinsics::load(&b);

    src.move_to(&mut dst);

    // dst should now contain a's data
    let mut output = [0u8; 16];
    dst.store(&mut output);
    assert_eq!(&output, &a);

    // src should be zeroized
    assert!(src.is_zeroized(), "Source should be zeroized after move_to");

    // Zeroize dst before drop
    dst.zeroize();
}

#[test]
fn test_debug_fmt() {
    if !has_aes_support() {
        return;
    }

    let data = hex_to_bytes_16("000102030405060708090a0b0c0d0e0f");
    let mut intrinsic = Intrinsics::load(&data);

    let debug_str = format!("{:?}", intrinsic);

    #[cfg(target_arch = "x86_64")]
    assert!(
        debug_str.contains("x86_64"),
        "Expected x86_64 in debug output"
    );

    #[cfg(target_arch = "aarch64")]
    assert!(
        debug_str.contains("aarch64"),
        "Expected aarch64 in debug output"
    );

    assert!(
        debug_str.contains("Intrinsics"),
        "Expected 'Intrinsics' in debug output"
    );
    assert!(
        debug_str.contains("[protected]"),
        "Expected '[protected]' to hide sensitive data"
    );

    // Zeroize before drop
    intrinsic.zeroize();
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "Intrinsics dropped without zeroization!")]
fn test_drop_panics_when_not_zeroized() {
    if !has_aes_support() {
        panic!("Intrinsics dropped without zeroization!"); // Fake panic to match should_panic
    }

    let data = hex_to_bytes_16("000102030405060708090a0b0c0d0e0f");
    let intrinsic = Intrinsics::load(&data);

    // Don't zeroize - should panic in Drop
    drop(intrinsic);
}

#[test]
fn test_drop_succeeds_when_zeroized() {
    if !has_aes_support() {
        return;
    }

    let data = hex_to_bytes_16("000102030405060708090a0b0c0d0e0f");
    let mut intrinsic = Intrinsics::load(&data);

    intrinsic.zeroize();

    // Should drop cleanly without panic
    drop(intrinsic);
}
