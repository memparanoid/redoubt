// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "wasi")
))]
mod tests {
    use crate::aead::Aead;
    use crate::feature_detector::{FeatureDetector, FeatureDetectorBehaviour};

    #[test]
    fn test_backend_detection() {
        let mut feature_detector = FeatureDetector::new();
        feature_detector.change_behaviour(FeatureDetectorBehaviour::ForceAesTrue);
        let aead = Aead::new_with_feature_detector(feature_detector);

        assert_eq!(aead.backend_name(), "AEGIS-128L");
    }

    #[test]
    fn test_roundtrip() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = aead.generate_nonce().expect("Failed to generate nonce");
        let aad = b"additional authenticated data";

        let mut plaintext = b"Hello, World! This is a test message.".to_vec();
        let mut tag = vec![0u8; aead.tag_size()];
        let original = plaintext.clone();

        // Encrypt
        aead.encrypt(&key, &nonce, aad, &mut plaintext, &mut tag)
            .expect("Encryption failed");

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
    fn test_wrong_tag_fails() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = aead.generate_nonce().expect("Failed to generate nonce");
        let aad = b"additional authenticated data";

        let mut plaintext = b"Hello, World!".to_vec();
        let mut tag = vec![0u8; aead.tag_size()];

        // Encrypt
        aead.encrypt(&key, &nonce, aad, &mut plaintext, &mut tag)
            .expect("Encryption failed");

        // Tamper with tag
        tag[0] ^= 1;

        // Decrypt should fail
        let result = aead.decrypt(&key, &nonce, aad, &mut plaintext, &tag);
        assert!(result.is_err(), "Decryption with wrong tag should fail");
    }

    #[test]
    fn test_size_methods() {
        let aead = Aead::with_aegis128l();

        assert_eq!(aead.key_size(), 16);
        assert_eq!(aead.nonce_size(), 16);
        assert_eq!(aead.tag_size(), 16);
    }

    #[test]
    fn test_debug_impl() {
        let aead = Aead::with_aegis128l();
        let debug_str = format!("{:?}", aead);
        assert_eq!(debug_str, "Aead { backend: AEGIS-128L }");
    }

    // Size validation tests
    #[test]
    fn test_encrypt_key_too_small() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 15]; // Should be 16
        let nonce = [0u8; 16];
        let mut plaintext = b"test".to_vec();
        let mut tag = [0u8; 16];

        let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
        assert!(result.is_err(), "Should fail with key too small");
    }

    #[test]
    fn test_encrypt_key_too_large() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 17]; // Should be 16
        let nonce = [0u8; 16];
        let mut plaintext = b"test".to_vec();
        let mut tag = [0u8; 16];

        let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
        assert!(result.is_err(), "Should fail with key too large");
    }

    #[test]
    fn test_encrypt_nonce_too_small() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = [0u8; 15]; // Should be 16
        let mut plaintext = b"test".to_vec();
        let mut tag = [0u8; 16];

        let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
        assert!(result.is_err(), "Should fail with nonce too small");
    }

    #[test]
    fn test_encrypt_nonce_too_large() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = [0u8; 17]; // Should be 16
        let mut plaintext = b"test".to_vec();
        let mut tag = [0u8; 16];

        let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
        assert!(result.is_err(), "Should fail with nonce too large");
    }

    #[test]
    fn test_encrypt_tag_too_small() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let mut plaintext = b"test".to_vec();
        let mut tag = [0u8; 15]; // Should be 16

        let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
        assert!(result.is_err(), "Should fail with tag too small");
    }

    #[test]
    fn test_encrypt_tag_too_large() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let mut plaintext = b"test".to_vec();
        let mut tag = [0u8; 17]; // Should be 16

        let result = aead.encrypt(&key, &nonce, b"", &mut plaintext, &mut tag);
        assert!(result.is_err(), "Should fail with tag too large");
    }

    #[test]
    fn test_decrypt_key_too_small() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 15]; // Should be 16
        let nonce = [0u8; 16];
        let mut ciphertext = b"test".to_vec();
        let tag = [0u8; 16];

        let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
        assert!(result.is_err(), "Should fail with key too small");
    }

    #[test]
    fn test_decrypt_key_too_large() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 17]; // Should be 16
        let nonce = [0u8; 16];
        let mut ciphertext = b"test".to_vec();
        let tag = [0u8; 16];

        let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
        assert!(result.is_err(), "Should fail with key too large");
    }

    #[test]
    fn test_decrypt_nonce_too_small() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = [0u8; 15]; // Should be 16
        let mut ciphertext = b"test".to_vec();
        let tag = [0u8; 16];

        let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
        assert!(result.is_err(), "Should fail with nonce too small");
    }

    #[test]
    fn test_decrypt_nonce_too_large() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = [0u8; 17]; // Should be 16
        let mut ciphertext = b"test".to_vec();
        let tag = [0u8; 16];

        let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
        assert!(result.is_err(), "Should fail with nonce too large");
    }

    #[test]
    fn test_decrypt_tag_too_small() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let mut ciphertext = b"test".to_vec();
        let tag = [0u8; 15]; // Should be 16

        let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
        assert!(result.is_err(), "Should fail with tag too small");
    }

    #[test]
    fn test_decrypt_tag_too_large() {
        let mut aead = Aead::with_aegis128l();

        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let mut ciphertext = b"test".to_vec();
        let tag = [0u8; 17]; // Should be 16

        let result = aead.decrypt(&key, &nonce, b"", &mut ciphertext, &tag);
        assert!(result.is_err(), "Should fail with tag too large");
    }
}
