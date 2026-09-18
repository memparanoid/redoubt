// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What one Wycheproof vector is, for each corpus this crate is held to.
//!
//! Written out here rather than in a file each, because the generated vectors
//! reach these by `super::<name>`, and what decides that path is a script that
//! writes more than one crate.
//!
//! The shapes are not interchangeable: a MAC vector is a key, a message and a
//! tag, and a derivation vector is keying material, a salt, an info and a
//! length. They share the corpus and nothing else.

/// One vector of `hmac_sha256_test.json`.
pub(crate) mod hmac_sha256_wycheproof {
    use alloc::string::String;
    use alloc::vec::Vec;

    /// What a vector was built to catch.
    ///
    /// Carried through so a failure names the family it came from: a tag that
    /// was modified and one generated at random are two different bugs with the
    /// same symptom.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Flag {
        /// The tag has been modified, which a partial comparison would miss.
        ModifiedTag,
        /// Pseudorandomly generated, for input sizes nobody thought to write
        /// down.
        Pseudorandom,
    }

    /// Whether the vector is one to accept or one to refuse.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum TestResult {
        Valid,
        Invalid,
        /// Neither, which this corpus does not use today.
        ///
        /// Kept because the generator emits it wherever a corpus has one, and a
        /// variant missing when that happens is a regeneration that stops
        /// compiling for a reason nobody asked about.
        #[expect(dead_code, reason = "the corpus has none of these today")]
        Acceptable,
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
        /// The message, hex.
        pub msg: String,
        /// The tag, hex. Shorter than a digest where the corpus truncates it.
        pub tag: String,
        /// Accept or refuse.
        pub result: TestResult,
    }
}

/// One vector of `hkdf_sha256_test.json`.
pub(crate) mod hkdf_sha256_wycheproof {
    use alloc::string::String;
    use alloc::vec::Vec;

    /// What a vector was built to catch.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Flag {
        /// Nothing unusual.
        Normal,
        /// No salt, which RFC 5869 §2.2 says behaves as a salt of zeros.
        EmptySalt,
        /// The last length the block counter has room for.
        MaximalOutputSize,
        /// A length past it, which is the one refusal a derivation has.
        SizeTooLarge,
        /// Distinct inputs that arrive at the same output.
        OutputCollision,
    }

    /// Whether the vector is one to accept or one to refuse.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum TestResult {
        Valid,
        Invalid,
        /// Neither, which this corpus does not use today.
        ///
        /// Kept because the generator emits it wherever a corpus has one, and a
        /// variant missing when that happens is a regeneration that stops
        /// compiling for a reason nobody asked about.
        #[expect(dead_code, reason = "the corpus has none of these today")]
        Acceptable,
    }

    /// One vector, with every field as the corpus publishes it.
    pub(crate) struct TestCase {
        /// Which vector this is, as the corpus numbers them.
        pub tc_id: usize,
        /// What the corpus says it is for.
        pub comment: String,
        /// What it was built to catch.
        pub flags: Vec<Flag>,
        /// The input keying material, hex.
        pub ikm: String,
        /// The salt, hex.
        pub salt: String,
        /// The info, hex.
        pub info: String,
        /// How many bytes are asked for.
        pub size: usize,
        /// The output keying material, hex.
        pub okm: String,
        /// Accept or refuse.
        pub result: TestResult,
    }
}

pub(crate) mod hkdf_sha256_wycheproof_vectors;
pub(crate) mod hmac_sha256_wycheproof_vectors;
