// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec::Vec;

use memaead::AeadApi;
use memcodec::{BytesRequired, DecodeZeroize, EncodeZeroize};

use crate::error::CipherBoxError;

pub trait EncryptStruct<A: AeadApi, const N: usize> {
    fn encrypt_into(
        &mut self,
        aead: &mut A,
        aead_key: &[u8],
        nonces: &mut [Vec<u8>; N],
        tags: &mut [Vec<u8>; N],
    ) -> Result<[Vec<u8>; N], CipherBoxError>;
}

pub trait CipherBoxDyns<const N: usize> {
    fn to_decryptable_dyn_fields(&mut self) -> [&mut dyn Decryptable; N];
    fn to_encryptable_dyn_fields(&mut self) -> [&mut dyn Encryptable; N];
}

pub trait DecryptStruct<A: AeadApi, const N: usize> {
    fn decrypt_from(
        &mut self,
        aead: &mut A,
        aead_key: &[u8],
        nonces: &mut [Vec<u8>; N],
        tags: &mut [Vec<u8>; N],
        ciphertexts: &mut [Vec<u8>; N],
    ) -> Result<(), CipherBoxError>;
}

pub trait Encryptable: BytesRequired + EncodeZeroize {}
pub trait Decryptable: DecodeZeroize {}

impl<T: BytesRequired + EncodeZeroize> Encryptable for T {}
impl<T: DecodeZeroize> Decryptable for T {}
