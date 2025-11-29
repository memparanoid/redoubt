// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::xchacha20poly1305::XChacha20Poly1305;
use crate::xchacha20poly1305::DecryptError;
use crate::xchacha20poly1305::consts::*;
use memalloc::AllockedVec;

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

/// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn xchacha20poly1305_decrypt_slice(
    key: &[u8],
    xnonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &mut [u8],
) -> Result<AllockedVec<u8>, DecryptError> {
    let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| DecryptError::InvalidNonceSize)?;
    let xnonce: &[u8; XNONCE_SIZE] = xnonce
        .try_into()
        .map_err(|_| DecryptError::InvalidNonceSize)?;
    let mut cipher = XChacha20Poly1305::default();
    cipher.decrypt(key, xnonce, aad, ciphertext_with_tag)
}

/// Run a single test case and return Ok if behavior matches expected result
fn run_test_case(tc: &TestCase) -> Result<(), String> {
    use crate::xchacha20poly1305::DecryptError;

    let key = hex_to_bytes(&tc.key);
    let nonce = hex_to_bytes(&tc.iv);
    let aad = hex_to_bytes(&tc.aad);
    let ct = hex_to_bytes(&tc.ct);
    let tag = hex_to_bytes(&tc.tag);

    // Combine ciphertext + tag (as Wycheproof stores them separately)
    let mut ciphertext_with_tag = ct;
    ciphertext_with_tag.extend_from_slice(&tag);

    let result = xchacha20poly1305_decrypt_slice(&key, &nonce, &aad, &mut ciphertext_with_tag);

    match (&tc.result, &result) {
        (TestResult::Valid, Ok(plaintext)) => {
            let expected_msg = hex_to_bytes(&tc.msg);
            if plaintext.as_slice() == expected_msg.as_slice() {
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
        (TestResult::Invalid, Ok(_)) => Err(format!(
            "tc_id {} ({}): expected invalid but decryption succeeded",
            tc.tc_id, tc.comment
        )),
        (TestResult::Invalid, Err(DecryptError::InvalidNonceSize)) => {
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
        (TestResult::Invalid, Err(DecryptError::AuthenticationFailed)) => {
            // ModifiedTag and other auth failures
            Ok(())
        }
        (TestResult::Invalid, Err(DecryptError::CiphertextTooShort)) => Ok(()),
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
    use crate::xchacha20poly1305::DecryptError;

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
        let ct = hex_to_bytes(&tc.ct);
        let mut tag = hex_to_bytes(&tc.tag);

        // Flip first bit of first byte
        tag[0] ^= 0x01;

        let mut ciphertext_with_tag = ct;
        ciphertext_with_tag.extend_from_slice(&tag);

        let result = xchacha20poly1305_decrypt_slice(&key, &nonce, &aad, &mut ciphertext_with_tag);

        match result {
            Err(DecryptError::AuthenticationFailed) => {
                // Expected
            }
            Ok(_) => {
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
