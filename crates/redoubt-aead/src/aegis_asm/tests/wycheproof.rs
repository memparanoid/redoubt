// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Wycheproof test vectors for AEGIS-128L

use redoubt_util::hex_to_bytes;

use crate::AeadError;
use crate::aegis_asm::Aegis128L;
use crate::traits::AeadBackend;

use super::super::consts::*;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flag {
    /// Known test vector from standards/specifications
    Ktv,
    /// Tag has been modified (authentication bypass test)
    ModifiedTag,
    /// Pseudorandomly generated inputs
    Pseudorandom,
    /// Old version of AEGIS-128L from https://eprint.iacr.org/2013/695.pdf
    OldVersion,
    /// Tag collision with different plaintext/ciphertext
    TagCollision1,
    /// Tag collision with different AAD
    TagCollision2,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestResult {
    Valid,
    Invalid,
    Acceptable,
}

/// A single Wycheproof test case for AEGIS-128L AEAD
pub(crate) struct TestCase {
    pub tc_id: usize,
    pub comment: String,
    #[allow(dead_code)]
    pub flags: Vec<Flag>,
    pub key: String,
    pub iv: String,
    pub aad: String,
    pub msg: String,
    pub ct: String,
    pub tag: String,
    pub result: TestResult,
}

fn run_test_case(tc: &TestCase) -> Result<(), String> {
    let key = hex_to_bytes(&tc.key);
    let nonce = hex_to_bytes(&tc.iv);
    let aad = hex_to_bytes(&tc.aad);
    let tag_vec = hex_to_bytes(&tc.tag);
    let mut data = hex_to_bytes(&tc.ct);

    // Validate sizes
    let key: [u8; KEY_SIZE] = match key.try_into() {
        Ok(k) => k,
        Err(_) => {
            return match tc.result {
                TestResult::Invalid | TestResult::Acceptable => Ok(()),
                TestResult::Valid => Err(format!("tc_id {}: invalid key size", tc.tc_id)),
            };
        }
    };

    let nonce: [u8; NONCE_SIZE] = match nonce.try_into() {
        Ok(n) => n,
        Err(_) => {
            return match tc.result {
                TestResult::Invalid | TestResult::Acceptable => Ok(()),
                TestResult::Valid => Err(format!("tc_id {}: invalid nonce size", tc.tc_id)),
            };
        }
    };

    let tag: [u8; TAG_SIZE] = match tag_vec.try_into() {
        Ok(t) => t,
        Err(_) => {
            return match tc.result {
                TestResult::Invalid | TestResult::Acceptable => Ok(()),
                TestResult::Valid => Err(format!("tc_id {}: invalid tag size", tc.tc_id)),
            };
        }
    };

    // Decrypt
    let mut aead = Aegis128L::default();
    let result = aead.decrypt(&key, &nonce, &aad, &mut data, &tag);

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
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        eprintln!("Skipping: AEGIS-128L requires AES hardware support");
        return;
    }

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

#[test]
fn test_wycheproof_valid_with_flipped_tag() {
    use super::wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if !matches!(tc.result, TestResult::Valid) {
            continue;
        }

        let key: [u8; KEY_SIZE] = hex_to_bytes(&tc.key)
            .try_into()
            .expect("Failed to convert hex to key");
        let nonce: [u8; NONCE_SIZE] = hex_to_bytes(&tc.iv)
            .try_into()
            .expect("Failed to convert hex to nonce");
        let aad = hex_to_bytes(&tc.aad);
        let mut data = hex_to_bytes(&tc.ct);
        let mut tag: [u8; TAG_SIZE] = hex_to_bytes(&tc.tag)
            .try_into()
            .expect("Failed to convert hex to tag");

        // Flip first bit
        tag[0] ^= 0x01;

        let mut aead = Aegis128L::default();
        let result = aead.decrypt(&key, &nonce, &aad, &mut data, &tag);

        match result {
            Err(AeadError::AuthenticationFailed) => {}
            Ok(()) => {
                failures.push(format!(
                    "tc_id {}: flipped tag accepted (should fail)",
                    tc.tc_id
                ));
            }
            Err(e) => {
                failures.push(format!("tc_id {}: unexpected error: {:?}", tc.tc_id, e));
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

#[test]
fn test_wycheproof_roundtrip() {
    use super::wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if !matches!(tc.result, TestResult::Valid) {
            continue;
        }

        let key: [u8; KEY_SIZE] = hex_to_bytes(&tc.key)
            .try_into()
            .expect("Failed to convert hex to key");
        let nonce: [u8; NONCE_SIZE] = hex_to_bytes(&tc.iv)
            .try_into()
            .expect("Failed to convert hex to nonce");
        let aad = hex_to_bytes(&tc.aad);
        let original_ct = hex_to_bytes(&tc.ct);
        let original_tag: [u8; TAG_SIZE] = hex_to_bytes(&tc.tag)
            .try_into()
            .expect("Failed to convert hex to tag");

        // Decrypt
        let mut data = original_ct.clone();
        let mut aead = Aegis128L::default();
        if let Err(e) = aead.decrypt(&key, &nonce, &aad, &mut data, &original_tag) {
            failures.push(format!("tc_id {}: decrypt failed: {:?}", tc.tc_id, e));
            continue;
        }

        // Re-encrypt
        let mut re_ct = data;
        let mut re_tag = [0u8; TAG_SIZE];
        aead.encrypt(&key, &nonce, &aad, &mut re_ct, &mut re_tag);

        if re_ct != original_ct || re_tag != original_tag {
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
