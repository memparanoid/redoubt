// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Test for standalone sha256_compress_block
//
// Test vectors from FIPS 180-4 and verified sources.
// Note: Block bytes are in big-endian order (as per SHA-256 spec).
//
// References:
// [1] FIPS 180-4: Secure Hash Standard (SHS)
//     https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf
//     Section 5.1.1 - SHA-256 examples
// [2] Crypto Stack Exchange: SHA-256 compression without padding
//     https://crypto.stackexchange.com/questions/99152/sha-256-compression-functions-without-padding

use crate::asm::sha256_compress_block;

#[test]
fn test_sha256_compress_abc() {
    // Test Vector 1: "abc" with SHA-256 padding (FIPS 180-4 Appendix E.1)
    // Message: "abc" (0x616263)
    // Padding: 0x80 + zeros + length (24 bits = 0x18)
    // Expected: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Block: "abc" = 0x616263, then 0x80, zeros, length 0x18 (24 bits) at end
    #[rustfmt::skip]
    let block: [u8; 64] = [
        0x61, 0x62, 0x63, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
    ];

    unsafe {
        sha256_compress_block(h.as_mut_ptr(), block.as_ptr());
    }

    let expected: [u32; 8] = [
        0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
        0xf20015ad,
    ];

    println!("Test 'abc':");
    println!("  Result:   {:08x?}", h);
    println!("  Expected: {:08x?}", expected);

    assert_eq!(h, expected, "SHA-256 compression mismatch for 'abc'");
}

#[test]
fn test_sha256_compress_empty() {
    // Test Vector 2: Empty message with padding (FIPS 180-4)
    // Message: "" (empty)
    // Padding: 0x80 + zeros + length (0 bits)
    // Expected: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[rustfmt::skip]
    let block: [u8; 64] = [
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    unsafe {
        sha256_compress_block(h.as_mut_ptr(), block.as_ptr());
    }

    let expected: [u32; 8] = [
        0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
        0x7852b855,
    ];

    println!("Test empty message:");
    println!("  Result:   {:08x?}", h);
    println!("  Expected: {:08x?}", expected);

    assert_eq!(
        h, expected,
        "SHA-256 compression mismatch for empty message"
    );
}

#[test]
fn test_sha256_compress_zero_block() {
    // Test Vector 3: Zero block (raw, no padding - for internal testing)
    // Block: all zeros
    // Expected output state from verified sources

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let block: [u8; 64] = [0u8; 64];

    unsafe {
        sha256_compress_block(h.as_mut_ptr(), block.as_ptr());
    }

    let expected: [u32; 8] = [
        0xda5698be, 0x17b9b469, 0x62335799, 0x779fbeca, 0x8ce5d491, 0xc0d26243, 0xbafef9ea,
        0x1837a9d8,
    ];

    println!("Test zero block:");
    println!("  Result:   {:08x?}", h);
    println!("  Expected: {:08x?}", expected);

    assert_eq!(h, expected, "SHA-256 compression mismatch for zero block");
}
