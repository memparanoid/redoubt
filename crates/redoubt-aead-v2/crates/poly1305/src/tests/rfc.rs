// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Every tag RFC 8439 publishes for Poly1305, against every backend.
//!
//! Appendix A.3 is the whole of it: the key and the message go in and the tag
//! comes out, and the eleven vectors differ in what they push — a small `r`
//! that forces the reduction, a message that ends on a block boundary, one that
//! does not.
//!
//! Both entry points are asked, because a caller reaches the tag either by
//! driving the state or by handing over the whole message at once, and nothing
//! makes the two agree except that both are held to this.

use rstest::rstest;

use redoubt_aead_v2_core::consts::poly1305::TAG_SIZE;
use redoubt_asm::Backend;

use crate::poly1305::tag_with_backend;

use crate::tests::support::tag_of;
use crate::tests::support::vectors::{VECTORS, Vector};

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_finalize_mut_returns_the_appendix_tag(#[case] backend: Backend) {
    for Vector {
        number,
        asks,
        key,
        message,
        tag: expected,
    } in VECTORS
    {
        assert_eq!(
            &tag_of(backend, key, message),
            expected,
            "RFC 8439 A.3 vector #{number} asks about {asks}"
        );
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_tag_with_backend_returns_the_appendix_tag(#[case] backend: Backend) {
    for Vector {
        number,
        asks,
        key,
        message,
        tag: expected,
    } in VECTORS
    {
        let mut tag = [0u8; TAG_SIZE];
        tag_with_backend(backend, key, message, &mut tag);

        assert_eq!(
            &tag, expected,
            "RFC 8439 A.3 vector #{number} asks about {asks}"
        );
    }
}
