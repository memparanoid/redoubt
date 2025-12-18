// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// // Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// // SPDX-License-Identifier: GPL-3.0-only
// // See LICENSE in the repository root for full license text.

// //! Tests for Aead with AEGIS-128L backend.

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// use crate::aead::Aead;
// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// use crate::feature_detector::{FeatureDetector, FeatureDetectorBehaviour};
// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// use crate::traits::AeadApi;

// // =============================================================================
// // Backend detection
// // =============================================================================

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_backend_detects_aegis128l_when_aes_available() {
//     let mut feature_detector = FeatureDetector::new();
//     feature_detector.change_behaviour(FeatureDetectorBehaviour::ForceAesTrue);
//     let aead = Aead::new_with_feature_detector(feature_detector);

//     assert_eq!(aead.backend_name(), "AEGIS-128L");
// }

// // =============================================================================
// // encrypt() + decrypt() roundtrip
// // =============================================================================

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_encrypt_decrypt_roundtrip() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = aead.generate_nonce().expect("Failed to generate_nonce()");
//     let aad = b"additional authenticated data";
//     let mut plaintext = b"Hello, World! This is a test message.".to_vec();
//     let mut tag = vec![0u8; aead.tag_size()];
//     let original = plaintext.clone();

//     aead.encrypt(&key, &nonce, aad, &mut plaintext, &mut tag)
//         .expect("Failed to encrypt(..)");

//     assert_ne!(plaintext, original);

//     aead.decrypt(&key, &nonce, aad, &mut plaintext, &tag)
//         .expect("Failed to decrypt(..)");

//     assert_eq!(plaintext, original);
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_decrypt_fails_with_wrong_tag() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = aead.generate_nonce().expect("Failed to generate_nonce()");
//     let aad = b"additional authenticated data";
//     let mut plaintext = b"Hello, World!".to_vec();
//     let mut tag = vec![0u8; aead.tag_size()];

//     aead.encrypt(&key, &nonce, aad, &mut plaintext, &mut tag)
//         .expect("Failed to encrypt(..)");

//     tag[0] ^= 1;

//     let result = aead.decrypt(&key, &nonce, aad, &mut plaintext, &tag);
//     assert!(result.is_err());
// }

// // =============================================================================
// // Size methods
// // =============================================================================

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_key_size_returns_correct_value() {
//     let aead = Aead::with_aegis128l();
//     assert_eq!(aead.key_size(), 16);
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_nonce_size_returns_correct_value() {
//     let aead = Aead::with_aegis128l();
//     assert_eq!(aead.nonce_size(), 16);
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_tag_size_returns_correct_value() {
//     let aead = Aead::with_aegis128l();
//     assert_eq!(aead.tag_size(), 16);
// }

// // =============================================================================
// // Debug impl
// // =============================================================================

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_debug_displays_backend_name() {
//     let aead = Aead::with_aegis128l();
//     let debug_str = format!("{:?}", aead);
//     assert_eq!(debug_str, "Aead { backend: AEGIS-128L }");
// }

// // =============================================================================
// // encrypt() - size validation errors
// // =============================================================================

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_encrypt_fails_with_key_too_small() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 15];
//     let nonce = [0u8; 16];
//     let mut plaintext = b"test".to_vec();
//     let mut tag = [0u8; 16];

//     let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_encrypt_fails_with_key_too_large() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 17];
//     let nonce = [0u8; 16];
//     let mut plaintext = b"test".to_vec();
//     let mut tag = [0u8; 16];

//     let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_encrypt_fails_with_nonce_too_small() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 15];
//     let mut plaintext = b"test".to_vec();
//     let mut tag = [0u8; 16];

//     let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_encrypt_fails_with_nonce_too_large() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 17];
//     let mut plaintext = b"test".to_vec();
//     let mut tag = [0u8; 16];

//     let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_encrypt_fails_with_tag_too_small() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 16];
//     let mut plaintext = b"test".to_vec();
//     let mut tag = [0u8; 15];

//     let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_encrypt_fails_with_tag_too_large() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 16];
//     let mut plaintext = b"test".to_vec();
//     let mut tag = [0u8; 17];

//     let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
//     assert!(result.is_err());
// }

// // =============================================================================
// // decrypt() - size validation errors
// // =============================================================================

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_decrypt_fails_with_key_too_small() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 15];
//     let nonce = [0u8; 16];
//     let mut ciphertext = b"test".to_vec();
//     let tag = [0u8; 16];

//     let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_decrypt_fails_with_key_too_large() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 17];
//     let nonce = [0u8; 16];
//     let mut ciphertext = b"test".to_vec();
//     let tag = [0u8; 16];

//     let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_decrypt_fails_with_nonce_too_small() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 15];
//     let mut ciphertext = b"test".to_vec();
//     let tag = [0u8; 16];

//     let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_decrypt_fails_with_nonce_too_large() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 17];
//     let mut ciphertext = b"test".to_vec();
//     let tag = [0u8; 16];

//     let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_decrypt_fails_with_tag_too_small() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 16];
//     let mut ciphertext = b"test".to_vec();
//     let tag = [0u8; 15];

//     let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
//     assert!(result.is_err());
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_decrypt_fails_with_tag_too_large() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 16];
//     let mut ciphertext = b"test".to_vec();
//     let tag = [0u8; 17];

//     let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
//     assert!(result.is_err());
// }

// // =============================================================================
// // AeadApi trait methods
// // =============================================================================

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_api_encrypt_succeeds() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 16];
//     let original = b"Hello, World! This is a test message.".to_vec();
//     let mut plaintext = original.clone();
//     let mut tag = vec![0u8; aead.api_tag_size()];

//     aead.api_encrypt(&key, &nonce, b"", &mut plaintext, &mut tag)
//         .expect("Failed to api_encrypt(..)");

//     assert_ne!(plaintext, original);
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_api_decrypt_succeeds() {
//     let mut aead = Aead::with_aegis128l();
//     let key = [0u8; 16];
//     let nonce = [0u8; 16];
//     let original = b"Hello, World! This is a test message.".to_vec();
//     let mut data = original.clone();
//     let mut tag = vec![0u8; aead.api_tag_size()];

//     aead.api_encrypt(&key, &nonce, b"", &mut data, &mut tag)
//         .expect("Failed to api_encrypt(..)");

//     aead.api_decrypt(&key, &nonce, b"", &mut data, &tag)
//         .expect("Failed to api_decrypt(..)");

//     assert_eq!(data, original);
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_api_generate_nonce_succeeds() {
//     let mut aead = Aead::with_aegis128l();

//     let nonce = aead
//         .api_generate_nonce()
//         .expect("Failed to api_generate_nonce()");

//     assert_eq!(nonce.len(), 16);
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_api_key_size_returns_correct_size() {
//     let aead = Aead::with_aegis128l();
//     assert_eq!(aead.api_key_size(), 16);
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_api_nonce_size_returns_correct_size() {
//     let aead = Aead::with_aegis128l();
//     assert_eq!(aead.api_nonce_size(), 16);
// }

// #[cfg(all(
//     any(target_arch = "x86_64", target_arch = "aarch64"),
//     not(target_os = "wasi")
// ))]
// #[test]
// fn test_api_tag_size_returns_correct_size() {
//     let aead = Aead::with_aegis128l();
//     assert_eq!(aead.api_tag_size(), 16);
// }
