// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec;
use alloc::vec::Vec;

use core::marker::PhantomData;

use redoubt_aead::AeadApi;
use memcodec::{BytesRequired, CodecBuffer, Decode, Encode};
use redoubt_zero::{
    FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeMetadata, ZeroizeOnDropSentinel,
    ZeroizingGuard,
};

use super::error::CipherBoxError;
use super::master_key::leak_master_key;

use super::consts::AAD;
use super::traits::{DecryptStruct, Decryptable, EncryptStruct, Encryptable};

#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
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
    healthy: bool,
    key_size: usize,
    ciphertexts: [Vec<u8>; N],
    nonces: [Vec<u8>; N],
    tags: [Vec<u8>; N],
    tmp_field_cyphertext: Vec<u8>,
    tmp_field_codec_buff: CodecBuffer,
    __sentinel: ZeroizeOnDropSentinel,
    #[fast_zeroize(skip)]
    aead: A,
    #[fast_zeroize(skip)]
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
    A: AeadApi,
{
    #[cfg(test)]
    pub(crate) fn __unsafe_change_api_key_size(&mut self, key_size: usize) {
        self.key_size = key_size;
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_tmp_ciphertext(&mut self) -> &Vec<u8> {
        &self.tmp_field_cyphertext
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_tmp_codec_buff(&mut self) -> &CodecBuffer {
        &self.tmp_field_codec_buff
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_field_ciphertext<const M: usize>(&mut self) -> &Vec<u8> {
        &self.ciphertexts[M]
    }

    pub fn new(aead: A) -> Self {
        let key_size = aead.api_key_size();
        let nonce_size = aead.api_nonce_size();
        let tag_size = aead.api_tag_size();

        let nonces: [Vec<u8>; N] = core::array::from_fn(|_| {
            let nonce = vec![0; nonce_size];
            nonce
        });

        let tags: [Vec<u8>; N] = core::array::from_fn(|_| {
            let tag = vec![0; tag_size];
            tag
        });

        let ciphertexts: [Vec<u8>; N] = core::array::from_fn(|_| vec![]);

        Self {
            aead,
            key_size,
            tags,
            nonces,
            ciphertexts,
            healthy: true,
            initialized: false,
            tmp_field_cyphertext: Vec::default(),
            tmp_field_codec_buff: CodecBuffer::default(),
            __sentinel: ZeroizeOnDropSentinel::default(),
            _marker: PhantomData,
        }
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn assert_healthy(&self) -> Result<(), CipherBoxError> {
        if !self.healthy {
            return Err(CipherBoxError::Poisoned);
        }

        Ok(())
    }

    #[inline(always)]
    pub fn encrypt_struct(&mut self, aead_key: &[u8], value: &mut T) -> Result<(), CipherBoxError> {
        let result = value.encrypt_into(&mut self.aead, aead_key, &mut self.nonces, &mut self.tags);

        match result {
            Ok(ciphertexts) => {
                self.ciphertexts = ciphertexts;
                Ok(())
            }
            Err(_) => {
                self.healthy = false;
                Err(CipherBoxError::Poisoned)
            }
        }
    }

    #[inline(always)]
    pub fn decrypt_struct(&mut self, aead_key: &[u8]) -> Result<ZeroizingGuard<T>, CipherBoxError> {
        let mut value = ZeroizingGuard::new(T::default());
        let result = value.decrypt_from(
            &mut self.aead,
            aead_key,
            &mut self.nonces,
            &mut self.tags,
            &mut self.ciphertexts,
        );

        match result {
            Ok(_) => Ok(value),
            Err(_) => {
                self.healthy = false;
                Err(CipherBoxError::Poisoned)
            }
        }
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn maybe_initialize(&mut self) -> Result<(), CipherBoxError> {
        if self.initialized {
            return Ok(());
        }

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.healthy = false;
            CipherBoxError::Poisoned
        })?;
        let mut value = ZeroizingGuard::new(T::default());

        self.encrypt_struct(&master_key, &mut value)?;
        self.initialized = true;

        Ok(())
    }

    #[inline(always)]
    fn try_decrypt_field<F, const M: usize>(
        &mut self,
        aead_key: &[u8],
        field: &mut F,
    ) -> Result<(), CipherBoxError>
    where
        F: Default + Decryptable + ZeroizationProbe,
    {
        // Clone ciphertext so we don't drain the original
        self.tmp_field_cyphertext = self.ciphertexts[M].clone();
        self.aead.api_decrypt(
            aead_key,
            &self.nonces[M],
            AAD,
            &mut self.tmp_field_cyphertext,
            &self.tags[M],
        )?;

        // tmp_field_cyphertext is guaranteed to be zeroized by `decode_from`
        field.decode_from(&mut self.tmp_field_cyphertext.as_mut_slice())?;

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn decrypt_field<F, const M: usize>(
        &mut self,
        aead_key: &[u8],
        field: &mut F,
    ) -> Result<(), CipherBoxError>
    where
        F: Default + Decryptable + ZeroizationProbe,
    {
        let result = self.try_decrypt_field::<F, M>(aead_key, field);

        if result.is_err() {
            self.healthy = false;
            return Err(CipherBoxError::Poisoned);
        }

        Ok(())
    }

    #[inline(always)]
    fn try_encrypt_field<F, const M: usize>(
        &mut self,
        aead_key: &[u8],
        field: &mut F,
    ) -> Result<(), CipherBoxError>
    where
        F: Encryptable,
    {
        let bytes_required = field.encode_bytes_required()?;

        self.tmp_field_codec_buff
            .realloc_with_capacity(bytes_required);

        field
            .encode_into(&mut self.tmp_field_codec_buff)
            .inspect_err(|_| {
                self.tmp_field_codec_buff.fast_zeroize();
            })?;

        self.ciphertexts[M] = self.tmp_field_codec_buff.export_as_vec();
        self.nonces[M] = self.aead.api_generate_nonce().inspect_err(|_| {
            self.ciphertexts[M].fast_zeroize();
        })?;
        self.aead
            .api_encrypt(
                aead_key,
                &self.nonces[M],
                AAD,
                &mut self.ciphertexts[M],
                &mut self.tags[M],
            )
            .inspect_err(|_| {
                self.ciphertexts[M].fast_zeroize();
            })?;

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn encrypt_field<F, const M: usize>(
        &mut self,
        aead_key: &[u8],
        field: &mut F,
    ) -> Result<(), CipherBoxError>
    where
        F: Encryptable,
    {
        let result = self.try_encrypt_field::<F, M>(aead_key, field);

        match result {
            Ok(()) => Ok(()),
            Err(CipherBoxError::Overflow(err)) => Err(CipherBoxError::Overflow(err)),
            Err(CipherBoxError::Entropy(err)) => Err(CipherBoxError::Entropy(err)),
            _ => {
                self.healthy = false;
                Err(CipherBoxError::Poisoned)
            }
        }
    }

    #[inline(always)]
    fn open_dyn(&mut self, f: &mut dyn Fn(&T)) -> Result<(), CipherBoxError> {
        self.assert_healthy()?;
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.healthy = false;
            CipherBoxError::Poisoned
        })?;
        let mut value = self.decrypt_struct(&master_key)?;

        f(&value);

        self.encrypt_struct(&master_key, &mut value)?;

        Ok(())
    }

    #[inline(always)]
    fn open_mut_dyn(&mut self, f: &mut dyn Fn(&mut T)) -> Result<(), CipherBoxError> {
        self.assert_healthy()?;
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.healthy = false;
            CipherBoxError::Poisoned
        })?;
        let mut value = self.decrypt_struct(&master_key)?;

        f(&mut value);

        self.encrypt_struct(&master_key, &mut value)?;

        Ok(())
    }

    #[inline(always)]
    pub fn open_field_dyn<Field, const M: usize>(
        &mut self,
        f: &mut dyn Fn(&Field),
    ) -> Result<(), CipherBoxError>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
    {
        self.assert_healthy()?;
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.healthy = false;
            CipherBoxError::Poisoned
        })?;
        let mut field = ZeroizingGuard::new(Field::default());

        self.decrypt_field::<Field, M>(&master_key, &mut field)?;
        f(&field);

        Ok(())
    }

    #[inline(always)]
    pub fn open_field_mut_dyn<Field, const M: usize>(
        &mut self,
        f: &mut dyn Fn(&mut Field),
    ) -> Result<(), CipherBoxError>
    where
        Field: Default + FastZeroizable + Encryptable + Decryptable + ZeroizationProbe,
    {
        self.assert_healthy()?;
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.healthy = false;
            CipherBoxError::Poisoned
        })?;
        let mut field = ZeroizingGuard::new(Field::default());

        self.decrypt_field::<Field, M>(&master_key, &mut field)?;
        f(&mut field);
        self.encrypt_field::<Field, M>(&master_key, &mut field)?;

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
    pub fn open_field<Field, const M: usize, F>(&mut self, mut f: F) -> Result<(), CipherBoxError>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
        F: Fn(&Field),
    {
        self.open_field_dyn::<Field, M>(&mut f)
    }

    #[inline(always)]
    pub fn open_field_mut<Field, const M: usize, F>(
        &mut self,
        mut f: F,
    ) -> Result<(), CipherBoxError>
    where
        Field: Default + FastZeroizable + Encryptable + Decryptable + ZeroizationProbe,
        F: Fn(&mut Field),
    {
        self.open_field_mut_dyn::<Field, M>(&mut f)
    }

    #[inline(always)]
    pub fn leak_field<Field, const M: usize>(
        &mut self,
    ) -> Result<ZeroizingGuard<Field>, CipherBoxError>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
    {
        self.assert_healthy()?;
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.healthy = false;
            CipherBoxError::Poisoned
        })?;
        let mut field = ZeroizingGuard::new(Field::default());

        self.decrypt_field::<Field, M>(&master_key, &mut field)?;

        Ok(field)
    }
}
