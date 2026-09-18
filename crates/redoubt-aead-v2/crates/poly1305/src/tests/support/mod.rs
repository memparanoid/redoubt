// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the cases are measured against, and the two ways of reaching a tag.

pub(crate) mod oracle;
pub(crate) mod vectors;

use redoubt_aead_v2_core::consts::poly1305::{KEY_SIZE, TAG_SIZE};
use redoubt_asm::Backend;

use crate::poly1305::Poly1305;

/// One message through one authenticator, whole.
pub(crate) fn tag_of(backend: Backend, key: &[u8; KEY_SIZE], message: &[u8]) -> [u8; TAG_SIZE] {
    let mut poly = Poly1305::new(key).with_backend(backend);
    let mut tag = [0u8; TAG_SIZE];

    poly.update(message);
    poly.finalize_mut(&mut tag);

    tag
}

/// One message handed over in two pieces split at `at`.
pub(crate) fn tag_of_split(
    backend: Backend,
    key: &[u8; KEY_SIZE],
    message: &[u8],
    at: usize,
) -> [u8; TAG_SIZE] {
    let mut poly = Poly1305::new(key).with_backend(backend);
    let mut tag = [0u8; TAG_SIZE];
    let (head, rest) = message.split_at(at);

    poly.update(head);
    poly.update(rest);
    poly.finalize_mut(&mut tag);

    tag
}
