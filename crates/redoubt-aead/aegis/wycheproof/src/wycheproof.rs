// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Wycheproof and implementation-specific test runners for AEGIS-128L backends.
//!
//! Includes Wycheproof conformance vectors plus internal tests for error paths
//! common to both x86 and ARM assembly implementations.

use redoubt_aead_core::{AeadApi, AeadError};
use redoubt_util::hex_to_bytes;

/// Wycheproof AEGIS-128L test case flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// Known test vector from standards/specifications
    Ktv,
    /// Tag has been modified (authentication bypass test)
    ModifiedTag,
    /// Pseudorandomly generated inputs
    Pseudorandom,
    /// Old version of AEGIS-128L
    OldVersion,
    /// Tag collision with different plaintext/ciphertext
    TagCollision1,
    /// Tag collision with different AAD
    TagCollision2,
}

/// Wycheproof test result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestResult {
    /// Valid test case
    Valid,
    /// Invalid test case
    Invalid,
    /// Acceptable test case
    /// It might be used in the future
    #[allow(dead_code)]
    Acceptable,
}

/// A single Wycheproof test case for AEGIS-128L AEAD.
pub struct TestCase {
    /// Unique test case identifier.
    pub tc_id: usize,
    /// Human-readable description.
    pub comment: String,
    /// Flags indicating what this test targets.
    /// It might be used in the future
    #[allow(dead_code)]
    pub flags: Vec<Flag>,
    /// Key (hex).
    pub key: String,
    /// Nonce/IV (hex).
    pub iv: String,
    /// Additional authenticated data (hex).
    pub aad: String,
    /// Plaintext message (hex).
    pub msg: String,
    /// Ciphertext (hex).
    pub ct: String,
    /// Authentication tag (hex).
    pub tag: String,
    /// Expected result.
    pub result: TestResult,
}

fn run_test_case(backend: &mut impl AeadApi, tc: &TestCase) -> Result<(), String> {
    let key = hex_to_bytes(&tc.key);
    let nonce = hex_to_bytes(&tc.iv);
    let aad = hex_to_bytes(&tc.aad);
    let tag_vec = hex_to_bytes(&tc.tag);
    let mut data = hex_to_bytes(&tc.ct);

    // Validate sizes
    if key.len() != backend.api_key_size() {
        return match tc.result {
            TestResult::Invalid | TestResult::Acceptable => Ok(()),
            TestResult::Valid => Err(format!("tc_id {}: invalid key size", tc.tc_id)),
        };
    }

    if nonce.len() != backend.api_nonce_size() {
        return match tc.result {
            TestResult::Invalid | TestResult::Acceptable => Ok(()),
            TestResult::Valid => Err(format!("tc_id {}: invalid nonce size", tc.tc_id)),
        };
    }

    if tag_vec.len() != backend.api_tag_size() {
        return match tc.result {
            TestResult::Invalid | TestResult::Acceptable => Ok(()),
            TestResult::Valid => Err(format!("tc_id {}: invalid tag size", tc.tc_id)),
        };
    }

    // Decrypt
    let result = backend.api_decrypt(&key, &nonce, &aad, &mut data, &tag_vec);

    match (&tc.result, &result) {
        (TestResult::Valid, Ok(())) => {
            let expected_msg = hex_to_bytes(&tc.msg);
            if data == expected_msg {
                Ok(())
            } else {
                Err(format!(
                    "tc_id {} ({}): plaintext mismatch",
                    tc.tc_id, tc.comment
                ))
            }
        }
        (TestResult::Valid, Err(e)) => Err(format!(
            "tc_id {} ({}): expected valid but got error: {:?}",
            tc.tc_id, tc.comment, e
        )),
        (TestResult::Invalid, Ok(())) => Err(format!(
            "tc_id {} ({}): expected invalid but decryption succeeded",
            tc.tc_id, tc.comment
        )),
        (TestResult::Invalid, Err(_)) => Ok(()),
        (TestResult::Acceptable, Ok(())) | (TestResult::Acceptable, Err(_)) => Ok(()),
    }
}

/// Run all AEGIS-128L Wycheproof test vectors against a backend.
pub fn run_aegis128l_wycheproof_tests(backend: &mut impl AeadApi) {
    use super::wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if let Err(msg) = run_test_case(backend, tc) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!(
            "AEGIS-128L Wycheproof test failures ({}/{}):\n{}",
            failures.len(),
            vectors.len(),
            failures.join("\n")
        );
    }
}

/// Run roundtrip test (decrypt then re-encrypt) on valid vectors.
pub fn run_aegis128l_roundtrip_tests(backend: &mut impl AeadApi) {
    use super::wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if !matches!(tc.result, TestResult::Valid) {
            continue;
        }

        let key = hex_to_bytes(&tc.key);
        let nonce = hex_to_bytes(&tc.iv);
        let aad = hex_to_bytes(&tc.aad);
        let original_ct = hex_to_bytes(&tc.ct);
        let original_tag = hex_to_bytes(&tc.tag);

        // Decrypt
        let mut data = original_ct.clone();

        if let Err(e) = backend.api_decrypt(&key, &nonce, &aad, &mut data, &original_tag) {
            failures.push(format!("tc_id {}: decrypt failed: {:?}", tc.tc_id, e));
            continue;
        }

        // Re-encrypt
        let mut re_ct = data;
        let mut re_tag = vec![0u8; backend.api_tag_size()];

        if let Err(e) = backend.api_encrypt(&key, &nonce, &aad, &mut re_ct, &mut re_tag) {
            failures.push(format!("tc_id {}: re-encrypt failed: {:?}", tc.tc_id, e));
            continue;
        }

        if re_ct != original_ct || re_tag != original_tag {
            failures.push(format!("tc_id {}: roundtrip mismatch", tc.tc_id));
        }
    }

    if !failures.is_empty() {
        panic!(
            "AEGIS-128L roundtrip test failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Run flipped-tag rejection test on valid vectors.
pub fn run_aegis128l_flipped_tag_tests(backend: &mut impl AeadApi) {
    use super::wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if !matches!(tc.result, TestResult::Valid) {
            continue;
        }

        let key = hex_to_bytes(&tc.key);
        let nonce = hex_to_bytes(&tc.iv);
        let aad = hex_to_bytes(&tc.aad);
        let mut data = hex_to_bytes(&tc.ct);
        let mut tag = hex_to_bytes(&tc.tag);

        // Flip first bit
        tag[0] ^= 0x01;

        let result = backend.api_decrypt(&key, &nonce, &aad, &mut data, &tag);

        match result {
            Err(_) => {}
            Ok(()) => {
                failures.push(format!(
                    "tc_id {}: flipped tag accepted (should fail)",
                    tc.tc_id
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "AEGIS-128L flipped tag test failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Run invalid size tests for encrypt error paths.
pub fn run_aegis128l_invalid_size_encrypt_tests(backend: &mut impl AeadApi) {
    let valid_key = vec![0u8; backend.api_key_size()];
    let valid_nonce = vec![0u8; backend.api_nonce_size()];
    let valid_tag_size = backend.api_tag_size();

    // Invalid key size
    let bad_key = vec![0u8; backend.api_key_size() + 1];
    let mut data = vec![0u8; 16];
    let mut tag = vec![0u8; valid_tag_size];
    let result = backend.api_encrypt(&bad_key, &valid_nonce, &[], &mut data, &mut tag);
    assert_eq!(result, Err(AeadError::InvalidKeySize));

    // Invalid nonce size
    let bad_nonce = vec![0u8; backend.api_nonce_size() + 1];
    let mut data = vec![0u8; 16];
    let mut tag = vec![0u8; valid_tag_size];
    let result = backend.api_encrypt(&valid_key, &bad_nonce, &[], &mut data, &mut tag);
    assert_eq!(result, Err(AeadError::InvalidNonceSize));

    // Invalid tag size
    let mut data = vec![0u8; 16];
    let mut bad_tag = vec![0u8; valid_tag_size + 1];
    let result = backend.api_encrypt(&valid_key, &valid_nonce, &[], &mut data, &mut bad_tag);
    assert_eq!(result, Err(AeadError::InvalidTagSize));
}

/// Run invalid size tests for decrypt error paths.
pub fn run_aegis128l_invalid_size_decrypt_tests(backend: &mut impl AeadApi) {
    let valid_key = vec![0u8; backend.api_key_size()];
    let valid_nonce = vec![0u8; backend.api_nonce_size()];
    let valid_tag_size = backend.api_tag_size();

    // Invalid key size
    let bad_key = vec![0u8; backend.api_key_size() + 1];
    let mut data = vec![0u8; 16];
    let tag = vec![0u8; valid_tag_size];
    let result = backend.api_decrypt(&bad_key, &valid_nonce, &[], &mut data, &tag);
    assert_eq!(result, Err(AeadError::InvalidKeySize));

    // Invalid nonce size
    let bad_nonce = vec![0u8; backend.api_nonce_size() + 1];
    let mut data = vec![0u8; 16];
    let tag = vec![0u8; valid_tag_size];
    let result = backend.api_decrypt(&valid_key, &bad_nonce, &[], &mut data, &tag);
    assert_eq!(result, Err(AeadError::InvalidNonceSize));

    // Invalid tag size
    let mut data = vec![0u8; 16];
    let bad_tag = vec![0u8; valid_tag_size + 1];
    let result = backend.api_decrypt(&valid_key, &valid_nonce, &[], &mut data, &bad_tag);
    assert_eq!(result, Err(AeadError::InvalidTagSize));
}

/// Run nonce generation test.
pub fn run_aegis128l_generate_nonce_test(backend: &mut impl AeadApi) {
    let nonce = backend
        .api_generate_nonce()
        .expect("Failed to generate AEGIS-128L nonce");
    assert_eq!(nonce.len(), backend.api_nonce_size());
}
