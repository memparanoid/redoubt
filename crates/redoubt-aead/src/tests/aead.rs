// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::aead::Aead;
use redoubt_aead_core::AeadError;

// =============================================================================
// encrypt() (XChaCha20-Poly1305)
// =============================================================================

#[test]
fn test_encrypt_xchacha_reports_invalid_key_size() {
    let mut aead = Aead::with_xchacha20poly1305();
    let bad_key = [0u8; 31]; // 32 expected
    let nonce = [0u8; 24];
    let mut data = [1u8; 8];
    let mut tag = [0u8; 16];

    let result = aead.encrypt(&bad_key, &nonce, &[], &mut data, &mut tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidKeySize)));
}

#[test]
fn test_encrypt_xchacha_reports_invalid_nonce_size() {
    let mut aead = Aead::with_xchacha20poly1305();
    let key = [0u8; 32];
    let bad_nonce = [0u8; 23]; // 24 expected
    let mut data = [1u8; 8];
    let mut tag = [0u8; 16];

    let result = aead.encrypt(&key, &bad_nonce, &[], &mut data, &mut tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidNonceSize)));
}

#[test]
fn test_encrypt_xchacha_reports_invalid_tag_size() {
    let mut aead = Aead::with_xchacha20poly1305();
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let mut data = [1u8; 8];
    let mut tag = [0u8; 15]; // 16 expected

    let result = aead.encrypt(&key, &nonce, &[], &mut data, &mut tag);
    assert!(result.is_err());

    assert!(matches!(result, Err(AeadError::InvalidTagSize)));
}

/// draft-irtf-cfrg-xchacha Appendix A.1
#[test]
fn test_encrypt_xchacha_succeeds() {
    let mut aead = Aead::with_xchacha20poly1305();

    #[rustfmt::skip]
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    #[rustfmt::skip]
    let nonce: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    #[rustfmt::skip]
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];

    let mut data = *b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let mut tag = [0u8; 16];

    let result = aead.encrypt(&key, &nonce, &aad, &mut data, &mut tag);

    assert!(result.is_ok());

    #[rustfmt::skip]
    let expected_ct: [u8; 114] = [
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b,
        0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9, 0x39,
        0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
        0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb,
        0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44,
        0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
        0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
        0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52,
        0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
        0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e,
        0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f,
        0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
        0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9,
        0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
        0xb5, 0x2e,
    ];
    #[rustfmt::skip]
    let expected_tag: [u8; 16] = [
        0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79,
        0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49,
    ];

    assert_eq!(&data, &expected_ct);
    assert_eq!(&tag, &expected_tag);
}

// =============================================================================
// decrypt() (XChaCha20-Poly1305)
// =============================================================================

#[test]
fn test_decrypt_xchacha_reports_invalid_key_size() {
    let mut aead = Aead::with_xchacha20poly1305();
    let bad_key = [0u8; 31];
    let nonce = [0u8; 24];
    let mut data = [1u8; 8];
    let tag = [0u8; 16];

    let result = aead.decrypt(&bad_key, &nonce, &[], &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidKeySize)));
}

#[test]
fn test_decrypt_xchacha_reports_invalid_nonce_size() {
    let mut aead = Aead::with_xchacha20poly1305();
    let key = [0u8; 32];
    let bad_nonce = [0u8; 23];
    let mut data = [1u8; 8];
    let tag = [0u8; 16];

    let result = aead.decrypt(&key, &bad_nonce, &[], &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidNonceSize)));
}

#[test]
fn test_decrypt_xchacha_reports_invalid_tag_size() {
    let mut aead = Aead::with_xchacha20poly1305();
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let mut data = [1u8; 8];
    let tag = [0u8; 15];

    let result = aead.decrypt(&key, &nonce, &[], &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidTagSize)));
}

#[test]
fn test_decrypt_xchacha_reports_authentication_failed() {
    let mut aead = Aead::with_xchacha20poly1305();
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let mut data = [1u8; 8];
    let tag = [0u8; 16];

    let result = aead.decrypt(&key, &nonce, &[], &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::AuthenticationFailed)));
}

/// draft-irtf-cfrg-xchacha Appendix A.1
#[test]
fn test_decrypt_xchacha_succeeds() {
    let mut aead = Aead::with_xchacha20poly1305();

    #[rustfmt::skip]
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    #[rustfmt::skip]
    let nonce: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    #[rustfmt::skip]
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];
    #[rustfmt::skip]
    let mut data: [u8; 114] = [
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b,
        0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9, 0x39,
        0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
        0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb,
        0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44,
        0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
        0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
        0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52,
        0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
        0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e,
        0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f,
        0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
        0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9,
        0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
        0xb5, 0x2e,
    ];
    #[rustfmt::skip]
    let tag: [u8; 16] = [
        0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79,
        0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49,
    ];

    let result = aead.decrypt(&key, &nonce, &aad, &mut data, &tag);

    assert!(result.is_ok());

    let expected = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    assert_eq!(&data, expected);
}

// =============================================================================
// encrypt() (AEGIS-128L)
// =============================================================================

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_encrypt_aegis_reports_invalid_key_size() {
    let mut aead = Aead::with_aegis128l();
    let bad_key = [0u8; 15]; // 16 expected
    let nonce = [0u8; 16];
    let mut data = [1u8; 8];
    let mut tag = [0u8; 16];

    let result = aead.encrypt(&bad_key, &nonce, &[], &mut data, &mut tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidKeySize)));
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_encrypt_aegis_reports_invalid_nonce_size() {
    let mut aead = Aead::with_aegis128l();
    let key = [0u8; 16];
    let bad_nonce = [0u8; 15]; // 16 expected
    let mut data = [1u8; 8];
    let mut tag = [0u8; 16];

    let result = aead.encrypt(&key, &bad_nonce, &[], &mut data, &mut tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidNonceSize)));
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_encrypt_aegis_reports_invalid_tag_size() {
    let mut aead = Aead::with_aegis128l();
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let mut data = [1u8; 8];
    let mut tag = [0u8; 15]; // 16 expected

    let result = aead.encrypt(&key, &nonce, &[], &mut data, &mut tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidTagSize)));
}

/// AEGIS-128L RFC Test Vector A.2.2 - Test Vector 1
#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_encrypt_aegis_succeeds() {
    let mut aead = Aead::with_aegis128l();

    #[rustfmt::skip]
    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut data: [u8; 16] = [0x00; 16];
    let mut tag = [0u8; 16];

    let result = aead.encrypt(&key, &nonce, &[], &mut data, &mut tag);

    assert!(result.is_ok());

    #[rustfmt::skip]
    let expected_ct: [u8; 16] = [
        0xc1, 0xc0, 0xe5, 0x8b, 0xd9, 0x13, 0x00, 0x6f,
        0xeb, 0xa0, 0x0f, 0x4b, 0x3c, 0xc3, 0x59, 0x4e,
    ];
    #[rustfmt::skip]
    let expected_tag: [u8; 16] = [
        0xab, 0xe0, 0xec, 0xe8, 0x0c, 0x24, 0x86, 0x8a,
        0x22, 0x6a, 0x35, 0xd1, 0x6b, 0xda, 0xe3, 0x7a,
    ];

    assert_eq!(&data, &expected_ct);
    assert_eq!(&tag, &expected_tag);
}

// =============================================================================
// decrypt() (AEGIS-128L)
// =============================================================================

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_decrypt_aegis_reports_invalid_key_size() {
    let mut aead = Aead::with_aegis128l();
    let bad_key = [0u8; 15];
    let nonce = [0u8; 16];
    let mut data = [1u8; 8];
    let tag = [0u8; 16];

    let result = aead.decrypt(&bad_key, &nonce, &[], &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidKeySize)));
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_decrypt_aegis_reports_invalid_nonce_size() {
    let mut aead = Aead::with_aegis128l();
    let key = [0u8; 16];
    let bad_nonce = [0u8; 15];
    let mut data = [1u8; 8];
    let tag = [0u8; 16];

    let result = aead.decrypt(&key, &bad_nonce, &[], &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidNonceSize)));
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_decrypt_aegis_reports_invalid_tag_size() {
    let mut aead = Aead::with_aegis128l();
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let mut data = [1u8; 8];
    let tag = [0u8; 15];

    let result = aead.decrypt(&key, &nonce, &[], &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::InvalidTagSize)));
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_decrypt_aegis_reports_authentication_failed() {
    let mut aead = Aead::with_aegis128l();
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let mut data = [1u8; 8];
    let tag = [0u8; 16];

    let result = aead.decrypt(&key, &nonce, &[], &mut data, &tag);

    assert!(result.is_err());
    assert!(matches!(result, Err(AeadError::AuthenticationFailed)));
}

/// AEGIS-128L RFC Test Vector A.2.2 - Test Vector 1
#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn test_decrypt_aegis_succeeds() {
    let mut aead = Aead::with_aegis128l();

    #[rustfmt::skip]
    let key: [u8; 16] = [
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    let nonce: [u8; 16] = [
        0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    let mut data: [u8; 16] = [
        0xc1, 0xc0, 0xe5, 0x8b, 0xd9, 0x13, 0x00, 0x6f,
        0xeb, 0xa0, 0x0f, 0x4b, 0x3c, 0xc3, 0x59, 0x4e,
    ];
    #[rustfmt::skip]
    let tag: [u8; 16] = [
        0xab, 0xe0, 0xec, 0xe8, 0x0c, 0x24, 0x86, 0x8a,
        0x22, 0x6a, 0x35, 0xd1, 0x6b, 0xda, 0xe3, 0x7a,
    ];

    let result = aead.decrypt(&key, &nonce, &[], &mut data, &tag);

    assert!(result.is_ok());
    assert_eq!(&data, &[0x00; 16]);
}
