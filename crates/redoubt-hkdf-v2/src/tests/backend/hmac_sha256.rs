// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HMAC-SHA256 against the answers RFC 4231 §4 publishes.
//!
//! Seven and not seven hundred, because HMAC has one decision in it: what to do
//! with a key that is not the width of a block. The seven cover a key shorter
//! than a block, a key of exactly the digest width, and a key of 131 bytes that
//! has to be hashed down first — and once both sides of that are in, a message
//! of another length says nothing further.
//!
//! Transcribed from the RFC rather than generated. Seven cases is a size where
//! a reader can check them against the document; a table a script wrote is a
//! second thing that can be wrong.

use rstest::rstest;

use redoubt_asm::Backend;

use crate::backend::hmac_sha256;
use crate::consts::HASH_SIZE;

use super::super::{from_hex, hex};

/// A case of RFC 4231 §4: the key, the data, and the tag, as the hex the
/// document writes them in.
struct Case {
    /// Which of §4.2 through §4.8 this is, so a failure names the section.
    at: &'static str,
    key: &'static str,
    data: &'static str,
    tag: &'static str,
}

/// The seven, in the order the document prints them.
///
/// Case 5 publishes a tag of sixteen bytes and not thirty-two: §4.6 is the
/// truncation case, and what it prints is the first half. It is compared
/// against the first half for that reason and not because anything here
/// truncates.
const CASES: [Case; 7] = [
    Case {
        at: "4.2, a twenty byte key",
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        tag: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    Case {
        at: "4.3, a four byte key",
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        tag: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    Case {
        at: "4.4, fifty bytes of data",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        tag: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    },
    Case {
        at: "4.5, a twenty-five byte key",
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        tag: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    },
    Case {
        at: "4.6, the truncation case",
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        tag: "a3b6167473100ee06e0c796c2955552b",
    },
    Case {
        at: "4.7, a key of 131 bytes, hashed first",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
        tag: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    },
    Case {
        at: "4.8, a key of 131 bytes and data past a block",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
        tag: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    },
];

// ============================================================================
// hmac_sha256
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hmac_answers_every_tag_rfc_4231_publishes(#[case] backend: Backend) {
    for case in &CASES {
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
