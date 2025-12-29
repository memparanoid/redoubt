// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use redoubt_util::hex_to_bytes;

use super::hmac_sha256_wycheproof_vectors::test_vectors;
use super::proxies::hmac::hmac_sha256;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flag {
    /// Modified MAC tag
    ModifiedTag,
    /// Pseudorandomly generated inputs
    Pseudorandom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestResult {
    Valid,
    Invalid,
    #[allow(dead_code)]
    Acceptable,
}

/// A single Wycheproof test case for HMAC-SHA-256
pub(crate) struct TestCase {
    /// Unique test case identifier
    pub tc_id: usize,
    /// Human-readable description
    pub comment: String,
    /// Flags indicating what this test targets
    pub flags: Vec<Flag>,
    /// Key (hex)
    pub key: String,
    /// Message (hex)
    pub msg: String,
    /// Expected MAC tag (hex)
    pub tag: String,
    /// Expected result
    pub result: TestResult,
}

fn run_test_case(tc: &TestCase) -> Result<(), String> {
    let key = hex_to_bytes(&tc.key);
    let msg = hex_to_bytes(&tc.msg);
    let expected_tag = hex_to_bytes(&tc.tag);

    let mut computed_tag = [0u8; 32];

    hmac_sha256(&key, &msg, &mut computed_tag);

    // Compare only the first expected_tag.len() bytes (for truncated MACs)
    let matches = &computed_tag[..expected_tag.len()] == expected_tag.as_slice();

    match (&tc.result, matches) {
        (TestResult::Valid, true) | (TestResult::Acceptable, true) => Ok(()),
        (TestResult::Valid, false) | (TestResult::Acceptable, false) => Err(format!(
            "tc_id {} ({}): MAC mismatch\n  expected: {}\n  got:      {}",
            tc.tc_id,
            tc.comment,
            tc.tag,
            hex::encode(&computed_tag[..expected_tag.len()])
        )),
        (TestResult::Invalid, true) => Err(format!(
            "tc_id {} ({}): expected invalid but MAC matched",
            tc.tc_id, tc.comment
        )),
        (TestResult::Invalid, false) => Ok(()), // Expected to fail
    }
}

// Minimal hex encoder for test output (avoid adding hex crate as dependency)
mod hex {
    use super::String;
    use super::format;

    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[test]
fn test_hmac_sha256_wycheproof_first_10() {
    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter().take(10) {
        if let Err(msg) = run_test_case(tc) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!(
            "HMAC-SHA256 Wycheproof test failures:\n{}",
            failures.join("\n")
        );
    }
}

#[test]
fn test_hmac_sha256_wycheproof_all() {
    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if let Err(msg) = run_test_case(tc) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!(
            "HMAC-SHA256 Wycheproof test failures ({}/{}):\n{}",
            failures.len(),
            vectors.len(),
            failures.join("\n")
        );
    }
}

/// Test that ModifiedTag vectors are properly rejected
#[test]
fn test_hmac_sha256_wycheproof_modified_tag() {
    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if !tc.flags.contains(&Flag::ModifiedTag) {
            continue;
        }

        if let Err(msg) = run_test_case(tc) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!(
            "HMAC-SHA256 modified tag test failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Test pseudorandom vectors
#[test]
fn test_hmac_sha256_wycheproof_pseudorandom() {
    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if !tc.flags.contains(&Flag::Pseudorandom) {
            continue;
        }

        if let Err(msg) = run_test_case(tc) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!(
            "HMAC-SHA256 pseudorandom test failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
