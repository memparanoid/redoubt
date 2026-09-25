// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::consts::HASH_SIZE;
use crate::sha256::sha256;

use crate::tests::{SHORT_MSG, SHORT_MSG_COUNT, hex, messages};

// === === === === === === === === === ===
// sha256
// === === === === === === === === === ===

#[test]
fn test_sha256_returns_every_short_message_digest() {
    for (message, expected) in messages(SHORT_MSG, SHORT_MSG_COUNT) {
        let mut out = [0_u8; HASH_SIZE];

        sha256(&message, &mut out);

        assert_eq!(hex(&out), expected, "{} bytes", message.len());
    }
}
