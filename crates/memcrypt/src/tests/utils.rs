// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::Aead;

pub fn create_aead_key(aead: &Aead, pattern: u8) -> Vec<u8> {
    let mut vec = Vec::<u8>::new();
    vec.resize_with(aead.key_size(), || pattern);
    vec
}

pub fn create_nonce(aead: &Aead, pattern: u8) -> Vec<u8> {
    let mut vec = Vec::<u8>::new();
    vec.resize_with(aead.nonce_size(), || pattern);
    vec
}
