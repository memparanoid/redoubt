// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memcodec::{BytesRequired, CodecBuffer};
use memzer::{DropSentinel, FastZeroizable, MemZer, ZeroizationProbe, ZeroizingMutGuard};

#[derive(MemZer)]
#[memzer(drop)]
pub struct EncryptionMemZer<'a, T: BytesRequired + FastZeroizable + ZeroizationProbe + Sized> {
    pub aead_key_size: usize,
    pub bytes_required: usize,
    pub codec_buf_len: usize,
    pub aead_key: ZeroizingMutGuard<'a, [u8]>,
    pub nonce: ZeroizingMutGuard<'a, [u8]>,
    pub value: ZeroizingMutGuard<'a, T>,
    pub buf: CodecBuffer,
    __drop_sentinel: DropSentinel,
}

impl<'a, T: BytesRequired + FastZeroizable + ZeroizationProbe + Sized> EncryptionMemZer<'a, T> {
    pub fn new(aead_key: &'a mut [u8], nonce: &'a mut [u8], value: &'a mut T) -> Self {
        let aead_key_size = aead_key.as_ref().len();

        Self {
            aead_key_size,
            bytes_required: 0,
            codec_buf_len: 0,
            aead_key: ZeroizingMutGuard::from(aead_key),
            nonce: ZeroizingMutGuard::from(nonce),
            value: ZeroizingMutGuard::from(value),
            buf: CodecBuffer::default(),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

#[derive(MemZer)]
#[memzer(drop)]
pub struct DecryptionMemZer<'a> {
    pub aead_key_size: usize,
    pub aead_key: ZeroizingMutGuard<'a, [u8]>,
    pub nonce: ZeroizingMutGuard<'a, [u8]>,
    pub ciphertext_with_tag: ZeroizingMutGuard<'a, [u8]>,
    __drop_sentinel: DropSentinel,
}

impl<'a> DecryptionMemZer<'a> {
    pub fn new(
        aead_key: &'a mut [u8],
        nonce: &'a mut [u8],
        ciphertext_with_tag: &'a mut [u8],
    ) -> Self {
        let aead_key_size = aead_key.as_ref().len();

        Self {
            aead_key_size,
            aead_key: ZeroizingMutGuard::from(aead_key),
            nonce: ZeroizingMutGuard::from(nonce),
            ciphertext_with_tag: ZeroizingMutGuard::from(ciphertext_with_tag),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}
