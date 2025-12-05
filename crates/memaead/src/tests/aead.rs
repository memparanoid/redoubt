// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{
    aead::Aead,
    feature_detector::{FeatureDetector, FeatureDetectorBehaviour},
};

#[test]
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "wasi")
))]
fn test_aegis128l_backend_detection() {
    let mut feature_detector = FeatureDetector::new();
    feature_detector.change_behaviour(FeatureDetectorBehaviour::ForceAesTrue);
    let aead = Aead::new_with_feature_detector(feature_detector);

    assert_eq!(aead.backend_name(), "AEGIS-128L");
}

#[test]
fn test_xchacha20poly1305_backend_fallback() {
    let mut feature_detector = FeatureDetector::new();
    feature_detector.change_behaviour(FeatureDetectorBehaviour::ForceAesFalse);
    let aead = Aead::new_with_feature_detector(feature_detector);

    assert_eq!(aead.backend_name(), "XChaCha20-Poly1305");
}

#[test]
fn test_xchacha20poly1305_roundtrip() {
    let mut aead = Aead::with_xchacha20poly1305();

    let key = [0u8; 32];
    let nonce = aead.generate_nonce().expect("Failed to generate nonce");
    let aad = b"additional authenticated data";

    let mut plaintext = b"Hello, World! This is a test message.".to_vec();
    let mut tag = vec![0u8; aead.tag_size()];
    let original = plaintext.clone();

    // Encrypt
    aead.encrypt(&key, &nonce, aad, &mut plaintext, &mut tag);

    // Verify ciphertext is different from plaintext
    assert_ne!(
        plaintext, original,
        "Ciphertext should differ from plaintext"
    );

    // Decrypt
    aead.decrypt(&key, &nonce, aad, &mut plaintext, &tag)
        .expect("Decryption failed");

    // Verify roundtrip
    assert_eq!(plaintext, original, "Decrypted text should match original");
}

#[test]
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "wasi")
))]
fn test_aegis128l_roundtrip() {
    let mut aead = Aead::with_aegis128l();

    let key = [0u8; 16];
    let nonce = aead.generate_nonce().expect("Failed to generate nonce");
    let aad = b"additional authenticated data";

    let mut plaintext = b"Hello, World! This is a test message.".to_vec();
    let mut tag = vec![0u8; aead.tag_size()];
    let original = plaintext.clone();

    // Encrypt
    aead.encrypt(&key, &nonce, aad, &mut plaintext, &mut tag);

    // Verify ciphertext is different from plaintext
    assert_ne!(
        plaintext, original,
        "Ciphertext should differ from plaintext"
    );

    // Decrypt
    aead.decrypt(&key, &nonce, aad, &mut plaintext, &tag)
        .expect("Decryption failed");

    // Verify roundtrip
    assert_eq!(plaintext, original, "Decrypted text should match original");
}

#[test]
fn test_xchacha20poly1305_wrong_tag_fails() {
    let mut aead = Aead::with_xchacha20poly1305();

    let key = [0u8; 32];
    let nonce = aead.generate_nonce().expect("Failed to generate nonce");
    let aad = b"additional authenticated data";

    let mut plaintext = b"Hello, World!".to_vec();
    let mut tag = vec![0u8; aead.tag_size()];

    // Encrypt
    aead.encrypt(&key, &nonce, aad, &mut plaintext, &mut tag);

    // Tamper with tag
    tag[0] ^= 1;

    // Decrypt should fail
    let result = aead.decrypt(&key, &nonce, aad, &mut plaintext, &tag);
    assert!(result.is_err(), "Decryption with wrong tag should fail");
}

#[test]
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "wasi")
))]
fn test_aegis128l_wrong_tag_fails() {
    let mut aead = Aead::with_aegis128l();

    let key = [0u8; 16];
    let nonce = aead.generate_nonce().expect("Failed to generate nonce");
    let aad = b"additional authenticated data";

    let mut plaintext = b"Hello, World!".to_vec();
    let mut tag = vec![0u8; aead.tag_size()];

    // Encrypt
    aead.encrypt(&key, &nonce, aad, &mut plaintext, &mut tag);

    // Tamper with tag
    tag[0] ^= 1;

    // Decrypt should fail
    let result = aead.decrypt(&key, &nonce, aad, &mut plaintext, &tag);
    assert!(result.is_err(), "Decryption with wrong tag should fail");
}

#[test]
fn test_backend_name() {
    let aead = Aead::new();
    let name = aead.backend_name();

    assert!(
        name == "AEGIS-128L" || name == "XChaCha20-Poly1305",
        "Backend name should be valid"
    );
}

#[test]
fn test_size_methods() {
    let aead = Aead::with_xchacha20poly1305();

    assert_eq!(aead.key_size(), 32);
    assert_eq!(aead.nonce_size(), 24);
    assert_eq!(aead.tag_size(), 16);

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(target_os = "wasi")
    ))]
    {
        let aead = Aead::with_aegis128l();

        assert_eq!(aead.key_size(), 16);
        assert_eq!(aead.nonce_size(), 16);
        assert_eq!(aead.tag_size(), 16);
    }
}

#[test]
fn test_debug_impl() {
    let aead = Aead::with_xchacha20poly1305();
    let debug_str = format!("{:?}", aead);

    assert_eq!(debug_str, "Aead { backend: XChaCha20-Poly1305 }");

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(target_os = "wasi")
    ))]
    {
        let aead = Aead::with_aegis128l();
        let debug_str = format!("{:?}", aead);
        assert_eq!(debug_str, "Aead { backend: AEGIS-128L }");
    }
}
