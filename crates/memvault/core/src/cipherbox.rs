// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::marker::PhantomData;

use memaead::AeadApi;
use memcodec::{BytesRequired, CodecBuffer, Decode, Encode};
use memzer::{
    DropSentinel, FastZeroizable, MemZer, ZeroizationProbe, ZeroizeMetadata, ZeroizingGuard,
};

use super::error::CipherBoxError;
use super::master_key::leak_master_key;

use super::consts::AAD;
use super::traits::{DecryptStruct, Decryptable, EncryptStruct, Encryptable};

#[derive(MemZer)]
#[memzer(drop)]
pub struct CipherBox<T, A, const N: usize>
where
    T: Default
        + FastZeroizable
        + ZeroizeMetadata
        + EncryptStruct<A, N>
        + DecryptStruct<A, N>
        + Encode
        + Decode
        + BytesRequired,
    A: AeadApi,
{
    initialized: bool,
    ciphertexts: [Vec<u8>; N],
    nonces: [Vec<u8>; N],
    tags: [Vec<u8>; N],
    __drop_sentinel: DropSentinel,
    #[memzer(skip)]
    aead: A,
    #[memzer(skip)]
    _marker: PhantomData<T>,
}

impl<T, A, const N: usize> CipherBox<T, A, N>
where
    T: Default
        + FastZeroizable
        + ZeroizeMetadata
        + ZeroizationProbe
        + EncryptStruct<A, N>
        + DecryptStruct<A, N>
        + Encode
        + Decode
        + BytesRequired,
    A: AeadApi + Default,
{
    pub fn new() -> Self {
        let aead = A::default();
        let nonce_size = aead.api_nonce_size();
        let tag_size = aead.api_tag_size();

        let nonces: [Vec<u8>; N] = core::array::from_fn(|_| {
            let mut nonce = Vec::with_capacity(nonce_size);
            nonce.resize(nonce_size, 0u8);
            nonce
        });

        let tags: [Vec<u8>; N] = core::array::from_fn(|_| {
            let mut tag = Vec::with_capacity(tag_size);
            tag.resize(tag_size, 0u8);
            tag
        });

        let ciphertexts: [Vec<u8>; N] = core::array::from_fn(|_| vec![]);

        Self {
            aead,
            tags,
            nonces,
            ciphertexts,
            initialized: false,
            __drop_sentinel: DropSentinel::default(),
            _marker: PhantomData,
        }
    }

    #[inline(always)]
    pub fn encrypt_struct(&mut self, aead_key: &[u8], value: &mut T) -> Result<(), CipherBoxError> {
        self.ciphertexts =
            value.encrypt_into(&mut self.aead, aead_key, &mut self.nonces, &mut self.tags)?;

        Ok(())
    }

    #[inline(always)]
    pub fn decrypt_struct(&mut self, aead_key: &[u8]) -> Result<ZeroizingGuard<T>, CipherBoxError> {
        let mut value = ZeroizingGuard::new(T::default());

        value.decrypt_from(
            &mut self.aead,
            aead_key,
            &mut self.nonces,
            &mut self.tags,
            &mut self.ciphertexts,
        )?;

        Ok(value)
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn maybe_initialize(&mut self) -> Result<(), CipherBoxError> {
        if self.initialized {
            return Ok(());
        }

        let master_key = leak_master_key(self.aead.api_key_size())?;
        let mut value = ZeroizingGuard::new(T::default());

        self.encrypt_struct(&master_key, &mut value)?;
        self.initialized = true;

        Ok(())
    }

    #[inline(always)]
    fn decrypt_field<F, const M: usize>(
        &mut self,
        aead_key: &[u8],
    ) -> Result<ZeroizingGuard<F>, CipherBoxError>
    where
        F: Default + Decryptable + ZeroizationProbe,
    {
        let mut field = ZeroizingGuard::new(F::default());

        // Clone ciphertext so we don't drain the original
        let mut ciphertext_copy = self.ciphertexts[M].clone();

        self.aead.api_decrypt(
            aead_key,
            &self.nonces[M],
            &AAD,
            &mut ciphertext_copy,
            &self.tags[M],
        )?;

        field.decode_from(&mut ciphertext_copy.as_mut_slice())?;
        // ciphertext_copy is dropped and zeroized here

        Ok(field)
    }

    #[inline(always)]
    fn encrypt_field<F, const M: usize>(
        &mut self,
        aead_key: &[u8],
        field: &mut F,
    ) -> Result<(), CipherBoxError>
    where
        F: Encryptable,
    {
        let size = field.mem_bytes_required()?;
        let mut buf = CodecBuffer::new(size);

        field.encode_into(&mut buf)?;

        self.ciphertexts[M] = buf.to_vec();
        self.nonces[M] = self.aead.api_generate_nonce()?;

        self.aead.api_encrypt(
            aead_key,
            &self.nonces[M],
            &AAD,
            &mut self.ciphertexts[M],
            &mut self.tags[M],
        )?;

        Ok(())
    }

    #[inline(always)]
    fn open_mut_dyn(&mut self, f: &mut dyn Fn(&mut T)) -> Result<(), CipherBoxError> {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.api_key_size())?;

        let mut value = self.decrypt_struct(&master_key)?;
        f(&mut value);
        self.encrypt_struct(&master_key, &mut value)?;

        Ok(())
    }

    #[inline(always)]
    fn open_dyn(&mut self, f: &mut dyn Fn(&T)) -> Result<(), CipherBoxError> {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.api_key_size())?;

        let mut value = self.decrypt_struct(&master_key)?;
        f(&value);
        self.encrypt_struct(&master_key, &mut value)?;

        Ok(())
    }

    #[inline(always)]
    pub fn open<F>(&mut self, mut f: F) -> Result<(), CipherBoxError>
    where
        F: Fn(&T),
    {
        self.open_dyn(&mut f)
    }

    #[inline(always)]
    pub fn open_mut<F>(&mut self, mut f: F) -> Result<(), CipherBoxError>
    where
        F: Fn(&mut T),
    {
        self.open_mut_dyn(&mut f)
    }

    #[inline(always)]
    pub fn open_field<Field, const M: usize, F>(&mut self, f: F) -> Result<(), CipherBoxError>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
        F: FnOnce(&Field),
    {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.api_key_size())?;

        let field = self.decrypt_field::<Field, M>(&master_key)?;
        f(&field);
        // No re-encrypt needed - ciphertext was cloned in decrypt_field

        Ok(())
    }

    #[inline(always)]
    pub fn open_field_mut<Field, const M: usize, F>(&mut self, f: F) -> Result<(), CipherBoxError>
    where
        Field: Default + FastZeroizable + Encryptable + Decryptable + ZeroizationProbe,
        F: FnOnce(&mut Field),
    {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.api_key_size())?;

        let mut field = self.decrypt_field::<Field, M>(&master_key)?;
        f(&mut field);
        self.encrypt_field::<Field, M>(&master_key, &mut field)?;

        Ok(())
    }

    #[inline(always)]
    pub fn leak_field<Field, const M: usize>(
        &mut self,
    ) -> Result<ZeroizingGuard<Field>, CipherBoxError>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
    {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.api_key_size())?;

        self.decrypt_field::<Field, M>(&master_key)
    }
}
