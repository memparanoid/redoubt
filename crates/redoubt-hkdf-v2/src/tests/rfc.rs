// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The answers the RFCs print, against both implementations.
//!
//! Transcribed from the documents rather than generated. At this size a reader
//! can check each case against the text it came from; a table a script wrote is
//! a second thing that can be wrong, and nothing checks it.
//!
//! What NIST publishes for the digest is read as a file instead, because there
//! are hundreds of those and a hundred transcriptions is not a size anybody
//! checks.

use alloc::vec;

use rstest::rstest;

use redoubt_asm::Backend;

use crate::backend::{hkdf_sha256, hmac_sha256};
use crate::consts::HASH_SIZE;

use super::{from_hex, hex};

/// A case of RFC 4231 §4: the key, the data, and the tag, as the hex the
/// document writes them in.
struct Authenticated {
    /// Which of §4.2 through §4.8 this is, so a failure names the section.
    at: &'static str,
    key: &'static str,
    data: &'static str,
    tag: &'static str,
}

/// A case of RFC 5869 appendix A: what goes in, and what comes out.
struct Derived {
    /// Which of A.1 through A.3 this is, so a failure names the section.
    at: &'static str,
    ikm: &'static str,
    salt: &'static str,
    info: &'static str,
    okm: &'static str,
}

/// RFC 4231 §4, in the order the document prints them.
///
/// What they reach between them is HMAC's one decision: a key shorter than a
/// block, a key the width of a digest, and a key of 131 bytes that has to be
/// hashed down before it can be padded. Once both sides of that are in, a
/// message of another length says nothing further.
///
/// The case at §4.6 publishes a tag of sixteen bytes and not thirty-two: it is
/// the truncation case, and what it prints is the first half. It is compared
/// against the first half for that reason and not because anything here
/// truncates.
const AUTHENTICATED: [Authenticated; 7] = [
    Authenticated {
        at: "4.2, a twenty byte key",
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        tag: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    Authenticated {
        at: "4.3, a four byte key",
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        tag: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    Authenticated {
        at: "4.4, fifty bytes of data",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        tag: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    },
    Authenticated {
        at: "4.5, a twenty-five byte key",
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        tag: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    },
    Authenticated {
        at: "4.6, the truncation case",
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        tag: "a3b6167473100ee06e0c796c2955552b",
    },
    Authenticated {
        at: "4.7, a key of 131 bytes, hashed first",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
        tag: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    },
    Authenticated {
        at: "4.8, a key of 131 bytes and data past a block",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
        tag: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    },
];

/// RFC 5869 appendix A, the cases that are SHA-256.
///
/// The appendix also prints cases for SHA-1, which belong to a construction
/// this crate does not have.
///
/// What they reach between them is the whole of the expansion's decisions: A.1
/// asks for less output than two digests fill, with a salt and an info to fold
/// in; A.2 asks for more, with inputs longer than a block; and A.3 asks with
/// neither a salt nor an info, which §2.2 says must behave as a salt of zeros.
const DERIVED: [Derived; 3] = [
    Derived {
        at: "A.1, the basic case",
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "000102030405060708090a0b0c",
        info: "f0f1f2f3f4f5f6f7f8f9",
        okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    },
    Derived {
        at: "A.2, inputs and output past a block",
        ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    Derived {
        at: "A.3, neither a salt nor an info",
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "",
        info: "",
        okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    },
];

// ============================================================================
// hmac_sha256
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hmac_answers_every_tag_rfc_4231_publishes(#[case] backend: Backend) {
    for case in &AUTHENTICATED {
        let key = from_hex(case.key);
        let data = from_hex(case.data);

        let mut out = [0_u8; HASH_SIZE];

        hmac_sha256(backend, &key, &data, &mut out);

        let answered = hex(&out);

        assert_eq!(
            &answered[..case.tag.len()],
            case.tag,
            "RFC 4231 §{}",
            case.at
        );
    }
}

// ============================================================================
// hkdf_sha256
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hkdf_answers_every_output_rfc_5869_publishes(#[case] backend: Backend) {
    for case in &DERIVED {
        let ikm = from_hex(case.ikm);
        let salt = from_hex(case.salt);
        let info = from_hex(case.info);

        let mut okm = vec![0_u8; case.okm.len() / 2];

        hkdf_sha256(backend, &salt, &ikm, &info, &mut okm);

        assert_eq!(hex(&okm), case.okm, "RFC 5869 §{}", case.at);
    }
}
