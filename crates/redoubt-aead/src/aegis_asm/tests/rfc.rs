// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(target_arch = "aarch64")]
use crate::aegis_asm::aead::{aegis128l_decrypt, aegis128l_encrypt, aegis128l_update};

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_update_rfc_vectors() {
    // Test vectors from AEGIS RFC: (Section A.2.1)

    // S0   : 9b7e60b24cc873ea894ecc07911049a3
    // S1   : 330be08f35300faa2ebf9a7b0d274658
    // S2   : 7bbd5bd2b049f7b9b515cf26fbe7756c
    // S3   : c35a00f55ea86c3886ec5e928f87db18
    // S4   : 9ebccafce87cab446396c4334592c91f
    // S5   : 58d83e31f256371e60fc6bb257114601
    // S6   : 1639b56ea322c88568a176585bc915de
    // S7   : 640818ffb57dc0fbc2e72ae93457e39a

    // M0   : 033e6975b94816879e42917650955aa0
    // M1   : fcc1968a46b7e97861bd6e89af6aa55f

    // After Update:

    // S0   : 596ab773e4433ca0127c73f60536769d
    // S1   : 790394041a3d26ab697bde865014652d
    // S2   : 38cf49e4b65248acd533041b64dd0611
    // S3   : 16d8e58748f437bfff1797f780337cee
    // S4   : 9689ecdf08228c74d7e3360cca53d0a5
    // S5   : a21746bb193a569e331e1aa985d0d729
    // S6   : 09d714e6fcf9177a8ed1cde7e3d259a6
    // S7   : 61279ba73167f0ab76f0a11bf203bdff

    // Initial state S0-S7
    let mut state: [u8; 128] = [
        // S0
        0x9b, 0x7e, 0x60, 0xb2, 0x4c, 0xc8, 0x73, 0xea, 0x89, 0x4e, 0xcc, 0x07, 0x91, 0x10, 0x49,
        0xa3, // S1
        0x33, 0x0b, 0xe0, 0x8f, 0x35, 0x30, 0x0f, 0xaa, 0x2e, 0xbf, 0x9a, 0x7b, 0x0d, 0x27, 0x46,
        0x58, // S2
        0x7b, 0xbd, 0x5b, 0xd2, 0xb0, 0x49, 0xf7, 0xb9, 0xb5, 0x15, 0xcf, 0x26, 0xfb, 0xe7, 0x75,
        0x6c, // S3
        0xc3, 0x5a, 0x00, 0xf5, 0x5e, 0xa8, 0x6c, 0x38, 0x86, 0xec, 0x5e, 0x92, 0x8f, 0x87, 0xdb,
        0x18, // S4
        0x9e, 0xbc, 0xca, 0xfc, 0xe8, 0x7c, 0xab, 0x44, 0x63, 0x96, 0xc4, 0x33, 0x45, 0x92, 0xc9,
        0x1f, // S5
        0x58, 0xd8, 0x3e, 0x31, 0xf2, 0x56, 0x37, 0x1e, 0x60, 0xfc, 0x6b, 0xb2, 0x57, 0x11, 0x46,
        0x01, // S6
        0x16, 0x39, 0xb5, 0x6e, 0xa3, 0x22, 0xc8, 0x85, 0x68, 0xa1, 0x76, 0x58, 0x5b, 0xc9, 0x15,
        0xde, // S7
        0x64, 0x08, 0x18, 0xff, 0xb5, 0x7d, 0xc0, 0xfb, 0xc2, 0xe7, 0x2a, 0xe9, 0x34, 0x57, 0xe3,
        0x9a,
    ];

    // Message blocks M0 and M1
    let m0: [u8; 16] = [
        0x03, 0x3e, 0x69, 0x75, 0xb9, 0x48, 0x16, 0x87, 0x9e, 0x42, 0x91, 0x76, 0x50, 0x95, 0x5a,
        0xa0,
    ];
    let m1: [u8; 16] = [
        0xfc, 0xc1, 0x96, 0x8a, 0x46, 0xb7, 0xe9, 0x78, 0x61, 0xbd, 0x6e, 0x89, 0xaf, 0x6a, 0xa5,
        0x5f,
    ];

    // Expected state after update
    let expected: [u8; 128] = [
        // S0
        0x59, 0x6a, 0xb7, 0x73, 0xe4, 0x43, 0x3c, 0xa0, 0x12, 0x7c, 0x73, 0xf6, 0x05, 0x36, 0x76,
        0x9d, // S1
        0x79, 0x03, 0x94, 0x04, 0x1a, 0x3d, 0x26, 0xab, 0x69, 0x7b, 0xde, 0x86, 0x50, 0x14, 0x65,
        0x2d, // S2
        0x38, 0xcf, 0x49, 0xe4, 0xb6, 0x52, 0x48, 0xac, 0xd5, 0x33, 0x04, 0x1b, 0x64, 0xdd, 0x06,
        0x11, // S3
        0x16, 0xd8, 0xe5, 0x87, 0x48, 0xf4, 0x37, 0xbf, 0xff, 0x17, 0x97, 0xf7, 0x80, 0x33, 0x7c,
        0xee, // S4
        0x96, 0x89, 0xec, 0xdf, 0x08, 0x22, 0x8c, 0x74, 0xd7, 0xe3, 0x36, 0x0c, 0xca, 0x53, 0xd0,
        0xa5, // S5
        0xa2, 0x17, 0x46, 0xbb, 0x19, 0x3a, 0x56, 0x9e, 0x33, 0x1e, 0x1a, 0xa9, 0x85, 0xd0, 0xd7,
        0x29, // S6
        0x09, 0xd7, 0x14, 0xe6, 0xfc, 0xf9, 0x17, 0x7a, 0x8e, 0xd1, 0xcd, 0xe7, 0xe3, 0xd2, 0x59,
        0xa6, // S7
        0x61, 0x27, 0x9b, 0xa7, 0x31, 0x67, 0xf0, 0xab, 0x76, 0xf0, 0xa1, 0x1b, 0xf2, 0x03, 0xbd,
        0xff,
    ];

    // Perform update
    unsafe {
        aegis128l_update(&mut state, &m0, &m1);
    }

    // Verify result matches RFC expected output
    assert_eq!(
        state, expected,
        "AEGIS-128L update does not match RFC test vector"
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_encrypt_16byte_msg() {
    // AEGIS-128L RFC Test Vector A.2.2 - Test Vector 1
    // key:   10010000000000000000000000000000
    // nonce: 10000200000000000000000000000000
    // ad:    (empty)
    // msg:   00000000000000000000000000000000
    // ct:    c1c0e58bd913006feba00f4b3cc3594e
    // tag:   abe0ece80c24868a226a35d16bdae37a

    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let mut data: [u8; 16] = [0x00; 16];
    let mut tag: [u8; 16] = [0xFF; 16];

    let expected_ciphertext: [u8; 16] = [
        0xc1, 0xc0, 0xe5, 0x8b, 0xd9, 0x13, 0x00, 0x6f, 0xeb, 0xa0, 0x0f, 0x4b, 0x3c, 0xc3, 0x59,
        0x4e,
    ];
    let expected_tag: [u8; 16] = [
        0xab, 0xe0, 0xec, 0xe8, 0x0c, 0x24, 0x86, 0x8a, 0x22, 0x6a, 0x35, 0xd1, 0x6b, 0xda, 0xe3,
        0x7a,
    ];

    unsafe {
        aegis128l_encrypt(
            &key,
            &nonce,
            std::ptr::null(), // No AAD
            0,                // AAD length = 0
            data.as_mut_ptr(),
            data.len(),
            &mut tag,
        );
    }

    assert_eq!(
        data, expected_ciphertext,
        "Ciphertext mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        data, expected_ciphertext
    );

    assert_eq!(
        tag, expected_tag,
        "Tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        tag, expected_tag
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_roundtrip_vector2_empty() {
    // AEGIS-128L RFC Test Vector A.2.3 - Test Vector 2
    // key:   10010000000000000000000000000000
    // nonce: 10000200000000000000000000000000
    // ad:    (empty)
    // msg:   (empty)
    // ct:    (empty)
    // tag:   c2b879a67def9d74e6c14f708bbcc9b4

    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let mut data: [u8; 0] = []; // Empty message
    let expected_tag: [u8; 16] = [
        0xc2, 0xb8, 0x79, 0xa6, 0x7d, 0xef, 0x9d, 0x74, 0xe6, 0xc1, 0x4f, 0x70, 0x8b, 0xbc, 0xc9,
        0xb4,
    ];

    let mut tag: [u8; 16] = [0xFF; 16];

    // === ENCRYPT ===
    unsafe {
        aegis128l_encrypt(
            &key,
            &nonce,
            std::ptr::null(),  // No AAD
            0,                 // AAD length = 0
            data.as_mut_ptr(), // Empty data
            data.len(),        // length = 0
            &mut tag,
        );
    }

    assert_eq!(
        tag, expected_tag,
        "Tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        tag, expected_tag
    );

    // === DECRYPT ===
    let mut computed_tag: [u8; 16] = [0xFF; 16];

    unsafe {
        aegis128l_decrypt(
            &key,
            &nonce,
            std::ptr::null(),
            0,
            data.as_mut_ptr(),
            data.len(),
            &expected_tag,
            &mut computed_tag,
        );
    }

    assert_eq!(
        computed_tag, expected_tag,
        "Computed tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        computed_tag, expected_tag
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_encrypt_decrypt_roundtrip() {
    // AEGIS-128L RFC Test Vector A.2.4 - Test Vector 3
    // key:   10010000000000000000000000000000
    // nonce: 10000200000000000000000000000000
    // ad:    0001020304050607
    // msg:   000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    // ct:    79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84
    // tag:   cc6f3372f6aa1bb82388d695c3962d9a

    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let aad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut plaintext: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let expected_ciphertext: [u8; 32] = [
        0x79, 0xd9, 0x45, 0x93, 0xd8, 0xc2, 0x11, 0x9d, 0x7e, 0x8f, 0xd9, 0xb8, 0xfc, 0x77, 0x84,
        0x5c, 0x5c, 0x07, 0x7a, 0x05, 0xb2, 0x52, 0x8b, 0x6a, 0xc5, 0x4b, 0x56, 0x3a, 0xed, 0x8e,
        0xfe, 0x84,
    ];
    let expected_tag: [u8; 16] = [
        0xcc, 0x6f, 0x33, 0x72, 0xf6, 0xaa, 0x1b, 0xb8, 0x23, 0x88, 0xd6, 0x95, 0xc3, 0x96, 0x2d,
        0x9a,
    ];

    // Save original plaintext for comparison after decrypt
    let original_plaintext = plaintext;

    let mut tag: [u8; 16] = [0xFF; 16];

    // === ENCRYPT ===
    unsafe {
        aegis128l_encrypt(
            &key,
            &nonce,
            aad.as_ptr(),
            aad.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
            &mut tag,
        );
    }

    // Verify plaintext buffer was overwritten with ciphertext
    assert_eq!(
        plaintext, expected_ciphertext,
        "Ciphertext (in-place) mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        plaintext, expected_ciphertext
    );

    assert_eq!(
        tag, expected_tag,
        "Tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        tag, expected_tag
    );

    // === DECRYPT ===
    // Now plaintext contains ciphertext, decrypt it in-place
    let mut computed_tag: [u8; 16] = [0xFF; 16];

    unsafe {
        aegis128l_decrypt(
            &key,
            &nonce,
            aad.as_ptr(),
            aad.len(),
            plaintext.as_mut_ptr(), // contains ciphertext, will be overwritten with plaintext
            plaintext.len(),
            &expected_tag,
            &mut computed_tag,
        );
    }

    assert_eq!(
        computed_tag, expected_tag,
        "Computed tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        computed_tag, expected_tag
    );

    // Verify in-place decrypt restored original plaintext
    assert_eq!(
        plaintext, original_plaintext,
        "Decrypted plaintext (in-place) mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        plaintext, original_plaintext
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_roundtrip_vector4_partial() {
    // AEGIS-128L RFC Test Vector A.2.5 - Test Vector 4
    // key:   10010000000000000000000000000000
    // nonce: 10000200000000000000000000000000
    // ad:    0001020304050607
    // msg:   000102030405060708090a0b0c0d (14 bytes - partial block)
    // ct:    79d94593d8c2119d7e8fd9b8fc77
    // tag:   5c04b3dba849b2701effbe32c7f0fab7

    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let aad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut plaintext: [u8; 14] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    ];
    let expected_ciphertext: [u8; 14] = [
        0x79, 0xd9, 0x45, 0x93, 0xd8, 0xc2, 0x11, 0x9d, 0x7e, 0x8f, 0xd9, 0xb8, 0xfc, 0x77,
    ];
    let expected_tag: [u8; 16] = [
        0x5c, 0x04, 0xb3, 0xdb, 0xa8, 0x49, 0xb2, 0x70, 0x1e, 0xff, 0xbe, 0x32, 0xc7, 0xf0, 0xfa,
        0xb7,
    ];

    // Save original plaintext for comparison after decrypt
    let original_plaintext = plaintext;

    let mut tag: [u8; 16] = [0xFF; 16];

    // === ENCRYPT ===
    unsafe {
        aegis128l_encrypt(
            &key,
            &nonce,
            aad.as_ptr(),
            aad.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
            &mut tag,
        );
    }

    // Verify plaintext buffer was overwritten with ciphertext
    assert_eq!(
        plaintext, expected_ciphertext,
        "Ciphertext (in-place) mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        plaintext, expected_ciphertext
    );

    assert_eq!(
        tag, expected_tag,
        "Tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        tag, expected_tag
    );

    // === DECRYPT ===
    // Now plaintext contains ciphertext, decrypt it in-place
    let mut computed_tag: [u8; 16] = [0xFF; 16];

    unsafe {
        aegis128l_decrypt(
            &key,
            &nonce,
            aad.as_ptr(),
            aad.len(),
            plaintext.as_mut_ptr(), // contains ciphertext, will be overwritten with plaintext
            plaintext.len(),
            &expected_tag,
            &mut computed_tag,
        );
    }

    assert_eq!(
        computed_tag, expected_tag,
        "Computed tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        computed_tag, expected_tag
    );

    // Verify in-place decrypt restored original plaintext
    assert_eq!(
        plaintext, original_plaintext,
        "Decrypted plaintext (in-place) mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        plaintext, original_plaintext
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_roundtrip_vector5_long() {
    // AEGIS-128L RFC Test Vector A.2.6 - Test Vector 5
    // key:   10010000000000000000000000000000
    // nonce: 10000200000000000000000000000000
    // ad:    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829 (42 bytes)
    // msg:   101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637 (40 bytes)
    // ct:    b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10
    // tag:   7542a745733014f9474417b337399507

    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let aad: [u8; 42] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    ];
    let mut plaintext: [u8; 40] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];
    let expected_ciphertext: [u8; 40] = [
        0xb3, 0x10, 0x52, 0xad, 0x1c, 0xca, 0x4e, 0x29, 0x1a, 0xbc, 0xf2, 0xdf, 0x35, 0x02, 0xe6,
        0xbd, 0xb1, 0xbf, 0xd6, 0xdb, 0x36, 0x79, 0x8b, 0xe3, 0x60, 0x7b, 0x1f, 0x94, 0xd3, 0x44,
        0x78, 0xaa, 0x7e, 0xde, 0x7f, 0x7a, 0x99, 0x0f, 0xec, 0x10,
    ];
    let expected_tag: [u8; 16] = [
        0x75, 0x42, 0xa7, 0x45, 0x73, 0x30, 0x14, 0xf9, 0x47, 0x44, 0x17, 0xb3, 0x37, 0x39, 0x95,
        0x07,
    ];

    // Save original plaintext for comparison after decrypt
    let original_plaintext = plaintext;

    let mut tag: [u8; 16] = [0xFF; 16];

    // === ENCRYPT ===
    unsafe {
        aegis128l_encrypt(
            &key,
            &nonce,
            aad.as_ptr(),
            aad.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
            &mut tag,
        );
    }

    // Verify plaintext buffer was overwritten with ciphertext
    assert_eq!(
        plaintext, expected_ciphertext,
        "Ciphertext (in-place) mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        plaintext, expected_ciphertext
    );

    assert_eq!(
        tag, expected_tag,
        "Tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        tag, expected_tag
    );

    // === DECRYPT ===
    // Now plaintext contains ciphertext, decrypt it in-place
    let mut computed_tag: [u8; 16] = [0xFF; 16];

    unsafe {
        aegis128l_decrypt(
            &key,
            &nonce,
            aad.as_ptr(),
            aad.len(),
            plaintext.as_mut_ptr(), // contains ciphertext, will be overwritten with plaintext
            plaintext.len(),
            &expected_tag,
            &mut computed_tag,
        );
    }

    assert_eq!(
        computed_tag, expected_tag,
        "Computed tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        computed_tag, expected_tag
    );

    // Verify in-place decrypt restored original plaintext
    assert_eq!(
        plaintext, original_plaintext,
        "Decrypted plaintext (in-place) mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
        plaintext, original_plaintext
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_negative_vector6_wrong_key() {
    // AEGIS-128L RFC Test Vector A.2.7 - Test Vector 6
    // This test MUST return a "verification failed" error.
    // key:   10000200000000000000000000000000 (WRONG - swapped with nonce)
    // nonce: 10010000000000000000000000000000
    // ad:    0001020304050607
    // ct:    79d94593d8c2119d7e8fd9b8fc77
    // tag:   5c04b3dba849b2701effbe32c7f0fab7

    let key: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // WRONG KEY
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let aad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut ciphertext: [u8; 14] = [
        0x79, 0xd9, 0x45, 0x93, 0xd8, 0xc2, 0x11, 0x9d, 0x7e, 0x8f, 0xd9, 0xb8, 0xfc, 0x77,
    ];
    let expected_tag: [u8; 16] = [
        0x5c, 0x04, 0xb3, 0xdb, 0xa8, 0x49, 0xb2, 0x70, 0x1e, 0xff, 0xbe, 0x32, 0xc7, 0xf0, 0xfa,
        0xb7,
    ];

    let mut computed_tag: [u8; 16] = [0xFF; 16];

    // === DECRYPT with WRONG KEY ===
    unsafe {
        aegis128l_decrypt(
            &key, // WRONG KEY
            &nonce,
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &expected_tag,
            &mut computed_tag,
        );
    }

    // Verify that computed tag does NOT match expected tag (verification should fail)
    assert_ne!(
        computed_tag, expected_tag,
        "Verification should fail with wrong key.\nComputed tag should NOT match expected tag."
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_negative_vector7_wrong_ct() {
    // AEGIS-128L RFC Test Vector A.2.8 - Test Vector 7
    // This test MUST return a "verification failed" error.
    // key:   10010000000000000000000000000000
    // nonce: 10000200000000000000000000000000
    // ad:    0001020304050607
    // ct:    79d94593d8c2119d7e8fd9b8fc78 (WRONG - last byte 0x78 instead of 0x77)
    // tag:   5c04b3dba849b2701effbe32c7f0fab7

    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let aad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut ciphertext: [u8; 14] = [
        0x79, 0xd9, 0x45, 0x93, 0xd8, 0xc2, 0x11, 0x9d, 0x7e, 0x8f, 0xd9, 0xb8, 0xfc,
        0x78, // WRONG - 0x78 instead of 0x77
    ];
    let expected_tag: [u8; 16] = [
        0x5c, 0x04, 0xb3, 0xdb, 0xa8, 0x49, 0xb2, 0x70, 0x1e, 0xff, 0xbe, 0x32, 0xc7, 0xf0, 0xfa,
        0xb7,
    ];

    let mut computed_tag: [u8; 16] = [0xFF; 16];

    // === DECRYPT with WRONG CIPHERTEXT ===
    unsafe {
        aegis128l_decrypt(
            &key,
            &nonce,
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_mut_ptr(), // WRONG CIPHERTEXT
            ciphertext.len(),
            &expected_tag,
            &mut computed_tag,
        );
    }

    // Verify that computed tag does NOT match expected tag (verification should fail)
    assert_ne!(
        computed_tag, expected_tag,
        "Verification should fail with wrong ciphertext.\nComputed tag should NOT match expected tag."
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_negative_vector8_wrong_aad() {
    // AEGIS-128L RFC Test Vector A.2.9 - Test Vector 8
    // This test MUST return a "verification failed" error.
    // key:   10010000000000000000000000000000
    // nonce: 10000200000000000000000000000000
    // ad:    0001020304050608 (WRONG - last byte 0x08 instead of 0x07)
    // ct:    79d94593d8c2119d7e8fd9b8fc77
    // tag:   5c04b3dba849b2701effbe32c7f0fab7

    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let aad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08]; // WRONG - 0x08 instead of 0x07
    let mut ciphertext: [u8; 14] = [
        0x79, 0xd9, 0x45, 0x93, 0xd8, 0xc2, 0x11, 0x9d, 0x7e, 0x8f, 0xd9, 0xb8, 0xfc, 0x77,
    ];
    let expected_tag: [u8; 16] = [
        0x5c, 0x04, 0xb3, 0xdb, 0xa8, 0x49, 0xb2, 0x70, 0x1e, 0xff, 0xbe, 0x32, 0xc7, 0xf0, 0xfa,
        0xb7,
    ];

    let mut computed_tag: [u8; 16] = [0xFF; 16];

    // === DECRYPT with WRONG AAD ===
    unsafe {
        aegis128l_decrypt(
            &key,
            &nonce,
            aad.as_ptr(), // WRONG AAD
            aad.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &expected_tag,
            &mut computed_tag,
        );
    }

    // Verify that computed tag does NOT match expected tag (verification should fail)
    assert_ne!(
        computed_tag, expected_tag,
        "Verification should fail with wrong AAD.\nComputed tag should NOT match expected tag."
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aegis128l_negative_vector9_wrong_tag() {
    // AEGIS-128L RFC Test Vector A.2.10 - Test Vector 9
    // This test MUST return a "verification failed" error.
    // key:   10010000000000000000000000000000
    // nonce: 10000200000000000000000000000000
    // ad:    0001020304050607
    // ct:    79d94593d8c2119d7e8fd9b8fc77
    // tag:   6c04b3dba849b2701effbe32c7f0fab8 (WRONG - first byte 0x6c instead of 0x5c, last byte 0xb8 instead of 0xb7)

    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let aad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut ciphertext: [u8; 14] = [
        0x79, 0xd9, 0x45, 0x93, 0xd8, 0xc2, 0x11, 0x9d, 0x7e, 0x8f, 0xd9, 0xb8, 0xfc, 0x77,
    ];
    let expected_tag: [u8; 16] = [
        0x6c, 0x04, 0xb3, 0xdb, 0xa8, 0x49, 0xb2, 0x70, // WRONG TAG
        0x1e, 0xff, 0xbe, 0x32, 0xc7, 0xf0, 0xfa, 0xb8,
    ];

    let mut computed_tag: [u8; 16] = [0xFF; 16];

    // === DECRYPT with WRONG TAG ===
    unsafe {
        aegis128l_decrypt(
            &key,
            &nonce,
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &expected_tag, // WRONG TAG
            &mut computed_tag,
        );
    }

    // Verify that computed tag does NOT match expected tag (verification should fail)
    assert_ne!(
        computed_tag, expected_tag,
        "Verification should fail with wrong tag.\nComputed tag should NOT match expected tag."
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
#[ignore] // Test after 16-byte works
fn test_aegis128l_encrypt_aligned() {
    // Test with 16-byte aligned buffers to isolate alignment issue
    #[repr(align(16))]
    struct Aligned16<T>(T);

    let key: Aligned16<[u8; 16]> = Aligned16([0x42; 16]);
    let nonce: Aligned16<[u8; 16]> = Aligned16([0x43; 16]);
    let mut data: Aligned16<[u8; 32]> = Aligned16([0x00; 32]);
    let mut tag: Aligned16<[u8; 16]> = Aligned16([0; 16]);
    let original_data = data.0;

    // Verify alignment
    assert_eq!((key.0.as_ptr() as usize) % 16, 0, "Key not aligned");
    assert_eq!((nonce.0.as_ptr() as usize) % 16, 0, "Nonce not aligned");
    assert_eq!((data.0.as_ptr() as usize) % 16, 0, "Data not aligned");

    unsafe {
        aegis128l_encrypt(
            &key.0,
            &nonce.0,
            std::ptr::null(), // No AAD
            0,                // AAD length = 0
            data.0.as_mut_ptr(),
            data.0.len(),
            &mut tag.0,
        );
    }

    // Verify ciphertext was written
    assert_ne!(data.0, original_data, "Data should have been transformed");

    println!("Ciphertext: {:02x?}", data.0);
    println!("Tag: {:02x?}", tag.0);
}
