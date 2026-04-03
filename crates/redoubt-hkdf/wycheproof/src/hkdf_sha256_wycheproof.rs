// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use redoubt_util::hex_to_bytes;

use redoubt_hkdf_core::HkdfApi;

/// Wycheproof HKDF test case flags.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// Standard valid test cases
    Normal,
    /// Tests with empty salt values
    EmptySalt,
    /// Edge cases with maximum permitted output (255 * 64 = 16320 bytes)
    MaximalOutputSize,
    /// Invalid requests exceeding 255 * hash digest size
    SizeTooLarge,
    /// Cases where distinct inputs produce identical outputs
    OutputCollision,
}

/// Wycheproof HKDF test result.
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

/// A single Wycheproof test case for HKDF-SHA-256.
pub struct TestCase {
    /// Unique test case identifier
    pub tc_id: usize,
    /// Human-readable description
    pub comment: String,
    /// Flags indicating what this test targets
    pub flags: Vec<Flag>,
    /// Input keying material (hex)
    pub ikm: String,
    /// Salt (hex)
    pub salt: String,
    /// Info/context (hex)
    pub info: String,
    /// Expected output size in bytes
    pub size: usize,
    /// Expected output keying material (hex)
    pub okm: String,
    /// Expected result
    pub result: TestResult,
}

fn run_test_case(backend: &mut impl HkdfApi, tc: &TestCase) -> Result<(), String> {
    let ikm = hex_to_bytes(&tc.ikm);
    let salt = hex_to_bytes(&tc.salt);
    let info = hex_to_bytes(&tc.info);
    let expected_okm = hex_to_bytes(&tc.okm);

    let mut out = vec![0u8; tc.size];
    let result = backend.api_hkdf(&salt, &ikm, &info, &mut out);

    match (&tc.result, &result) {
        (TestResult::Valid, Ok(())) | (TestResult::Acceptable, Ok(())) => {
            if out == expected_okm {
                Ok(())
            } else {
                Err(format!(
                    "tc_id {} ({}): output mismatch\n  expected: {}\n  got:      {}",
                    tc.tc_id,
                    tc.comment,
                    tc.okm,
                    hex::encode(&out)
                ))
            }
        }
        (TestResult::Valid, Err(e)) | (TestResult::Acceptable, Err(e)) => Err(format!(
            "tc_id {} ({}): expected valid but got error: {:?}",
            tc.tc_id, tc.comment, e
        )),
        (TestResult::Invalid, Ok(())) => Err(format!(
            "tc_id {} ({}): expected invalid but derivation succeeded",
            tc.tc_id, tc.comment
        )),
        (TestResult::Invalid, Err(_)) => Ok(()),
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

/// Run all HKDF-SHA256 Wycheproof test vectors against a backend.
pub fn run_hkdf_wycheproof_tests(backend: &mut impl HkdfApi) {
    use super::hkdf_sha256_wycheproof_vectors::test_vectors;

    let vectors = test_vectors();
    let mut failures = Vec::new();

    for tc in vectors.iter() {
        if let Err(msg) = run_test_case(backend, tc) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!(
            "HKDF-SHA256 Wycheproof test failures ({}/{}):\n{}",
            failures.len(),
            vectors.len(),
            failures.join("\n")
        );
    }
}
