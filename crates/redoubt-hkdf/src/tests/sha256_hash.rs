// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Test for sha256_hash (full SHA-256 with padding)
//
// References:
// [1] FIPS 180-4: Secure Hash Standard (SHS)
//     https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf
//     Section 6.2 - SHA-256 examples
// [2] NIST SHA-256 Examples PDF
//     https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/SHA256.pdf
// [3] RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
//     https://www.rfc-editor.org/rfc/rfc6234.html#section-5.3
// [4] NIST CAVP (Cryptographic Algorithm Validation Program)
//     https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

use super::proxies::sha256::sha256_hash;

#[cfg(target_arch = "aarch64")]
#[test]
fn test_sha256_hash_abc() {
    // Test Vector: SHA-256("abc") from FIPS 180-4
    let msg = b"abc";
    let mut digest = [0u8; 32];

    sha256_hash(msg, &mut digest);

    // Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    println!("SHA-256('abc'):");
    println!("  Result:   {:02x?}", digest);
    println!("  Expected: {:02x?}", expected);

    assert_eq!(digest, expected, "SHA-256 hash mismatch for 'abc'");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_sha256_hash_empty() {
    // Test Vector: SHA-256("") from FIPS 180-4
    let msg = b"";
    let mut digest = [0u8; 32];

    sha256_hash(msg, &mut digest);

    // Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    println!("SHA-256(''):");
    println!("  Result:   {:02x?}", digest);
    println!("  Expected: {:02x?}", expected);

    assert_eq!(digest, expected, "SHA-256 hash mismatch for empty message");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_sha256_hash_56_bytes() {
    // Test Vector 3: 56-byte message (RFC 6234, Section 5.3 - TEST2_1)
    // Exactly 56 bytes forces a second block with only padding + length
    // Message: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(msg.len(), 56, "Test vector should be 56 bytes");

    let mut digest = [0u8; 32];

    sha256_hash(msg, &mut digest);

    // Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
    let expected = [
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60,
        0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb,
        0x06, 0xc1,
    ];

    println!("SHA-256(56-byte message):");
    println!("  Result:   {:02x?}", digest);
    println!("  Expected: {:02x?}", expected);

    assert_eq!(
        digest, expected,
        "SHA-256 hash mismatch for 56-byte message"
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_sha256_hash_112_bytes() {
    // Test Vector 4: 112-byte message (RFC 4634/6234 - multi-block test)
    // Two complete blocks (64 + 48 + padding in second block)
    // Verifies state chaining between blocks
    // Message: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
    //           hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(msg.len(), 112, "Test vector should be 112 bytes");

    let mut digest = [0u8; 32];

    sha256_hash(msg, &mut digest);

    // Expected: cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1
    let expected = [
        0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92,
        0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe,
        0xe9, 0xd1,
    ];

    println!("SHA-256(112-byte message):");
    println!("  Result:   {:02x?}", digest);
    println!("  Expected: {:02x?}", expected);

    assert_eq!(
        digest, expected,
        "SHA-256 hash mismatch for 112-byte message"
    );
}
