// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use memzer::{
    DropSentinel, MemEncodeBuf, MemZer, Secret, Zeroizable, ZeroizationProbe, ZeroizingMutGuard,
};

use crate::aead_buffer::AeadBuffer;
use crate::aead_key::AeadKey;
use crate::xnonce::XNonce;

#[derive(Zeroize, MemZer)]
#[zeroize(drop)]
pub struct EncryptionMemZer<'a, T: Zeroize + Zeroizable + ZeroizationProbe + Sized> {
    pub aead_key: ZeroizingMutGuard<'a, AeadKey>,
    pub aead_key_size: usize,
    pub xnonce: ZeroizingMutGuard<'a, XNonce>,
    pub value: ZeroizingMutGuard<'a, T>,
    pub buf: MemEncodeBuf,
    pub aead_buffer: AeadBuffer,
    __drop_sentinel: DropSentinel,
}

impl<'a, T: Zeroize + Zeroizable + ZeroizationProbe + Sized> EncryptionMemZer<'a, T> {
    pub fn new(aead_key: &'a mut AeadKey, xnonce: &'a mut XNonce, value: &'a mut T) -> Self {
        let aead_key_size = aead_key.as_ref().len();

        Self {
            aead_key_size,
            aead_key: ZeroizingMutGuard::from(aead_key),
            xnonce: ZeroizingMutGuard::from(xnonce),
            value: ZeroizingMutGuard::from(value),
            buf: MemEncodeBuf::default(),
            aead_buffer: AeadBuffer::default(),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

#[derive(Zeroize, MemZer)]
#[zeroize(drop)]
pub struct DecryptionMemZer<'a> {
    pub aead_key: ZeroizingMutGuard<'a, AeadKey>,
    pub aead_key_size: usize,
    pub xnonce: ZeroizingMutGuard<'a, XNonce>,
    pub ciphertext: ZeroizingMutGuard<'a, Secret<Vec<u8>>>,
    pub aead_buffer: AeadBuffer,
    __drop_sentinel: DropSentinel,
}

impl<'a> DecryptionMemZer<'a> {
    pub fn new(
        aead_key: &'a mut AeadKey,
        xnonce: &'a mut XNonce,
        ciphertext: &'a mut Secret<Vec<u8>>,
    ) -> Self {
        let aead_key_size = aead_key.as_ref().len();

        Self {
            aead_key_size,
            aead_key: ZeroizingMutGuard::from(aead_key),
            xnonce: ZeroizingMutGuard::from(xnonce),
            ciphertext: ZeroizingMutGuard::from(ciphertext),
            aead_buffer: AeadBuffer::default(),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}
