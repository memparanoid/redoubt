// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the cases are measured against, and the two ways of reaching a tag.

pub(crate) mod oracle;
pub(crate) mod vectors;

use redoubt_aead_core::consts::poly1305::{KEY_SIZE, TAG_SIZE};
use redoubt_asm::Backend;

use crate::poly1305::Poly1305;
use crate::tests::support::vectors::{VECTORS, Vector};

/// One keyed under the backend named.
pub(crate) fn keyed(backend: Backend, key: &[u8; KEY_SIZE]) -> Poly1305 {
    let mut poly = Poly1305::new();

    poly.init(backend, key);

    poly
}

/// One message through one authenticator, whole.
pub(crate) fn tag_of(backend: Backend, key: &[u8; KEY_SIZE], message: &[u8]) -> [u8; TAG_SIZE] {
    let mut poly = keyed(backend, key);
    let mut tag = [0u8; TAG_SIZE];

    poly.update(backend, message);
    poly.finalize_mut(backend, &mut tag);

    tag
}

/// One message handed over in two pieces split at `at`.
pub(crate) fn tag_of_split(
    backend: Backend,
    key: &[u8; KEY_SIZE],
    message: &[u8],
    at: usize,
) -> [u8; TAG_SIZE] {
    let mut poly = keyed(backend, key);
    let mut tag = [0u8; TAG_SIZE];
    let (head, rest) = message.split_at(at);

    poly.update(backend, head);
    poly.update(backend, rest);
    poly.finalize_mut(backend, &mut tag);

    tag
}

/// Every published vector through `compute`, which is the one thing that
/// differs between the ways of reaching a tag.
pub(crate) fn against_the_appendix(compute: impl Fn(&[u8; KEY_SIZE], &[u8], &mut [u8; TAG_SIZE])) {
    for Vector {
        number,
        asks,
        key,
        message,
        tag: expected,
    } in VECTORS
    {
        let mut out = [0u8; TAG_SIZE];

        compute(key, message, &mut out);

        assert_eq!(
            &out, expected,
            "RFC 8439 A.3 vector #{number} asks about {asks}"
        );
    }
}
