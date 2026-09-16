// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What one Wycheproof vector is, and what the corpus says about itself.
//!
//! Here rather than beside the test that reads them because the generated file
//! reaches these by `super::wycheproof`, and it is generated — moving them
//! means changing a script that writes two crates.

use std::string::String;
use std::vec::Vec;

/// What a vector was built to catch.
///
/// Carried through so a failure names the family it came from: a tag that
/// should have been rejected and one that exercises the modular addition are
/// two different bugs with the same symptom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flag {
    /// An edge case in the ciphertext.
    EdgeCaseCiphertext,
    /// An edge case in the integer arithmetic Poly1305 is computed with,
    /// where an overflow would show.
    EdgeCasePoly1305,
    /// A Poly1305 key with edge-case values — a limb of zero, say.
    EdgeCasePolyKey,
    /// An edge case in the tag, which is the final modular addition.
    EdgeCaseTag,
    /// A nonce of a size the construction does not take.
    InvalidNonceSize,
    /// A vector published by a standard.
    Ktv,
    /// The tag has been modified, which a partial verification would miss.
    ModifiedTag,
    /// Pseudorandomly generated, for input sizes nobody thought to write down.
    Pseudorandom,
}

/// Whether the vector is one to accept or one to refuse.
pub(crate) enum TestResult {
    Valid,
    Invalid,
}

/// One vector, with every field as the corpus publishes it.
///
/// The bytes arrive as hex because that is what the JSON holds and what the
/// generator writes; the harness is what turns them into the widths this
/// construction takes.
pub(crate) struct TestCase {
    /// Which vector this is, as the corpus numbers them.
    pub tc_id: usize,
    /// What the corpus says it is for.
    pub comment: String,
    /// What it was built to catch.
    pub flags: Vec<Flag>,
    /// The key, hex.
    pub key: String,
    /// The nonce, hex. The corpus calls it `iv`.
    pub iv: String,
    /// The associated data, hex.
    pub aad: String,
    /// The plaintext, hex.
    pub msg: String,
    /// The ciphertext without its tag, hex.
    pub ct: String,
    /// The tag, hex.
    pub tag: String,
    /// Accept or refuse.
    pub result: TestResult,
}
