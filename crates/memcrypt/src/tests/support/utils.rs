// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::aead_key::AeadKey;
use crate::xnonce::XNonce;

pub fn create_key_from_array(mut bytes: [u8; 32]) -> AeadKey {
    let mut key = AeadKey::default();
    key.fill_exact(&mut bytes);
    key
}

pub fn create_xnonce_from_array(mut bytes: [u8; 24]) -> XNonce {
    let mut xnonce = XNonce::default();
    xnonce.fill_exact(&mut bytes);
    xnonce
}
