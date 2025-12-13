// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memutil::hex_to_bytes;

use crate::AeadError;
use crate::traits::AeadBackend;
use crate::xchacha20poly1305::XChacha20Poly1305;
use crate::xchacha20poly1305::consts::*;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flag {
    /// The test vector contains an edge case for the ciphertext.
    EdgeCaseCiphertext,

    /// The test vector contains an edge case for the integer arithmetic used to compute Poly1305.
    /// Goal: catch integer overflows in Poly1305 computation.
    EdgeCasePoly1305,

    /// The test vector contains values where the Poly1305 key has edge case values
    /// (e.g., limbs with value 0). Goal: detect incorrect integer arithmetic in Poly1305.
    EdgeCasePolyKey,

    /// The tag contains an edge case. Goal: check for arithmetic errors in the final
    /// modular addition of CHACHA-POLY-1305.
    EdgeCaseTag,

    /// RFC 7539 restricts nonce size to 12 bytes (ChaCha20-Poly1305) or 24 bytes (XChaCha20-Poly1305).
    /// This test uses an invalid nonce size.
    InvalidNonceSize,

    /// Known test vector from standards/specifications.
    Ktv,

    /// The ciphertext tag has been modified. Goal: detect implementations with partial
    /// or incorrect tag verification (authentication bypass).
    ModifiedTag,

    /// Pseudorandomly generated inputs. Goal: check implementation for different input sizes.
    Pseudorandom,
}

pub(crate) enum TestResult {
    Valid,
    Invalid,
}

/// A single Wycheproof test case for XChaCha20-Poly1305 AEAD
pub(crate) struct TestCase {
    /// Unique test case identifier (e.g., 1, 2, 3...)
    pub tc_id: usize,

    /// Human-readable description of the test (e.g., "empty plaintext", "modified tag")
    pub comment: String,

    /// List of flags indicating what vulnerability or edge case this test targets
    pub flags: Vec<Flag>,

    /// 32-byte encryption key as hex string (e.g., "0000...0000")
    pub key: String,

    /// Nonce/IV as hex string (12 bytes for ChaCha20-Poly1305, 24 bytes for XChaCha20-Poly1305)
    /// Note: Wycheproof JSON uses "iv" field name
    pub iv: String,

    /// Additional authenticated data (AAD) as hex string
    pub aad: String,

    /// Plaintext message as hex string
    pub msg: String,

    /// Expected ciphertext as hex string (without tag)
    pub ct: String,

    /// Expected authentication tag as hex string (16 bytes)
    pub tag: String,

    /// Expected test result: Valid (must accept) or Invalid (must reject)
    pub result: TestResult,
}

fn xchacha20poly1305_encrypt(
    key: &[u8],
    xnonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
    tag_out: &mut [u8; TAG_SIZE],
) -> Result<(), AeadError> {
    let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
    let xnonce: &[u8; XNONCE_SIZE] = xnonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
    let mut aead = XChacha20Poly1305::default();
    aead.encrypt(key, xnonce, aad, data, tag_out);
    Ok(())
}

fn xchacha20poly1305_decrypt(
    key: &[u8],
    xnonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_SIZE],
) -> Result<(), AeadError> {
    let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
    let xnonce: &[u8; XNONCE_SIZE] = xnonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
    let mut aead = XChacha20Poly1305::default();
    aead.decrypt(key, xnonce, aad, data, tag)
}

/// Run a single test case and return Ok if behavior matches expected result
fn run_test_case(tc: &TestCase) -> Result<(), String> {
    use crate::error::AeadError;

    let key = hex_to_bytes(&tc.key);
    let nonce = hex_to_bytes(&tc.iv);
    let aad = hex_to_bytes(&tc.aad);
    let tag_vec = hex_to_bytes(&tc.tag);
    let tag: [u8; TAG_SIZE] = match tag_vec.try_into() {
        Ok(t) => t,
        Err(_) => {
            // Invalid tag size - with new API this is rejected at compile time,
            // but Wycheproof tests include these cases
            return match tc.result {
                TestResult::Invalid => Ok(()), // Expected to fail
                TestResult::Valid => Err(format!(
                    "tc_id {}: invalid tag size on valid test",
                    tc.tc_id
                )),
            };
        }
    };
    let mut data = hex_to_bytes(&tc.ct);

    let result = xchacha20poly1305_decrypt(&key, &nonce, &aad, &mut data, &tag);

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
        (TestResult::Invalid, Err(AeadError::InvalidNonceSize)) => {
            // InvalidNonceSize flag should map to this error
            if tc.flags.contains(&Flag::InvalidNonceSize) {
                Ok(())
            } else {
                Err(format!(
                    "tc_id {} ({}): unexpected InvalidNonceSize error",
                    tc.tc_id, tc.comment
                ))
            }
        }
        (TestResult::Invalid, Err(AeadError::AuthenticationFailed)) => {
            // ModifiedTag and other auth failures
            Ok(())
        }
        (TestResult::Invalid, Err(AeadError::InvalidTagSize | AeadError::InvalidKeySize)) => {
            // Size validation errors (invalid test vectors)
            Ok(())
        }
    }
}

#[test]
fn test_wycheproof_first_10() {
    use super::wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter().take(10) {
        if let Err(msg) = run_test_case(tc) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!("Wycheproof test failures:\n{}", failures.join("\n"));
    }
}

#[test]
fn test_wycheproof_all() {
    use super::wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if let Err(msg) = run_test_case(tc) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!(
            "Wycheproof test failures ({}/{}):\n{}",
            failures.len(),
            vectors.len(),
            failures.join("\n")
        );
    }
}

/// For every valid test case, flip a bit in the tag and verify authentication fails
#[test]
fn test_wycheproof_valid_with_flipped_tag() {
    use super::wycheproof_vectors::test_vectors;
    use crate::AeadError;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        // Only test valid cases
        if !matches!(tc.result, TestResult::Valid) {
            continue;
        }

        let key = hex_to_bytes(&tc.key);
        let nonce = hex_to_bytes(&tc.iv);
        let aad = hex_to_bytes(&tc.aad);
        let mut data = hex_to_bytes(&tc.ct);
        let mut tag: [u8; TAG_SIZE] = hex_to_bytes(&tc.tag).try_into().expect("Failed to convert hex to tag");

        // Flip first bit of first byte
        tag[0] ^= 0x01;

        let result = xchacha20poly1305_decrypt(&key, &nonce, &aad, &mut data, &tag);

        match result {
            Err(AeadError::AuthenticationFailed) => {
                // Expected
            }
            Ok(()) => {
                failures.push(format!(
                    "tc_id {}: flipped tag accepted (should have been rejected)",
                    tc.tc_id
                ));
            }
            Err(e) => {
                failures.push(format!(
                    "tc_id {}: unexpected error with flipped tag: {:?}",
                    tc.tc_id, e
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "Flipped tag test failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// For every valid test case, decrypt then re-encrypt and verify we get the same ciphertext+tag
#[test]
fn test_wycheproof_roundtrip() {
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
        let original_tag: [u8; TAG_SIZE] = hex_to_bytes(&tc.tag).try_into().expect("Failed to convert hex to tag");

        // Decrypt
        let mut data = original_ct.clone();
        if let Err(e) = xchacha20poly1305_decrypt(&key, &nonce, &aad, &mut data, &original_tag) {
            failures.push(format!("tc_id {}: decrypt failed: {:?}", tc.tc_id, e));
            continue;
        }
        // data now contains plaintext

        // Re-encrypt
        let mut re_encrypted_ct = data; // plaintext
        let mut re_encrypted_tag = [0u8; TAG_SIZE];
        if let Err(e) = xchacha20poly1305_encrypt(
            &key,
            &nonce,
            &aad,
            &mut re_encrypted_ct,
            &mut re_encrypted_tag,
        ) {
            failures.push(format!("tc_id {}: encrypt failed: {:?}", tc.tc_id, e));
            continue;
        }

        // Verify roundtrip
        if re_encrypted_ct != original_ct || re_encrypted_tag != original_tag {
            failures.push(format!("tc_id {}: roundtrip mismatch", tc.tc_id));
        }
    }

    if !failures.is_empty() {
        panic!(
            "Roundtrip test failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
