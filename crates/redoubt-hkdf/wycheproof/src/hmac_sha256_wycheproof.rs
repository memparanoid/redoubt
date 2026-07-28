// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use redoubt_util::hex_to_bytes;

use redoubt_hkdf_core::HkdfApi;

/// Iterates the vector corpus, sampled with a fixed stride under Miri.
///
/// Wycheproof vectors are not interchangeable: each targets a distinct edge —
/// tags with arithmetic corner cases, empty AAD, boundary lengths — so taking a
/// prefix would drop whole families. A stride lands across all of them.
///
/// Sampling is sound for what Miri is doing here. It looks for undefined
/// behaviour on a code path, and the path is identical for vector 3 and vector
/// 300; what changes between vectors is the arithmetic, which Miri does not
/// check and `cargo test` verifies exhaustively in seconds. Running the full
/// corpus under interpretation costs hours and adds nothing.
fn corpus<T>(vectors: &[T]) -> impl Iterator<Item = &T> {
    #[cfg(miri)]
    let step = (vectors.len() / 16).max(1);

    #[cfg(not(miri))]
    let step = 1;

    vectors.iter().step_by(step)
}

/// Wycheproof HMAC test case flags.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// Modified MAC tag
    ModifiedTag,
    /// Pseudorandomly generated inputs
    Pseudorandom,
}

/// Wycheproof HMAC test result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestResult {
    /// Valid test case
    Valid,
    /// Invalid test case
    Invalid,
    /// Acceptable test case
    #[allow(dead_code)]
    Acceptable,
}

/// A single Wycheproof test case for HMAC-SHA-256.
pub struct TestCase {
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

fn run_test_case(backend: &mut impl HkdfApi, tc: &TestCase) -> Result<(), String> {
    let key = hex_to_bytes(&tc.key);
    let msg = hex_to_bytes(&tc.msg);
    let expected_tag = hex_to_bytes(&tc.tag);

    let mut computed_tag = [0u8; 32];

    backend.api_hmac_sha256(&key, &msg, &mut computed_tag);

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
        (TestResult::Invalid, false) => Ok(()),
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

/// Run all HMAC-SHA256 Wycheproof test vectors against a backend.
pub fn run_hmac_wycheproof_tests(backend: &mut impl HkdfApi) {
    use super::hmac_sha256_wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in corpus(&vectors) {
        if let Err(msg) = run_test_case(backend, tc) {
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
