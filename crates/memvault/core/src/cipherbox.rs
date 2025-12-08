// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::marker::PhantomData;

use memaead::Aead;
use membuffer::BufferError;
use memcodec::{BytesRequired, CodecBuffer, Decode, Encode};
use memcrypt::{decrypt_decodable, encrypt_encodable};
use memhkdf::hkdf;
use memrand::{EntropySource, SystemEntropySource};
use memzer::{
    DropSentinel, FastZeroizable, MemZer, ZeroizationProbe, ZeroizeMetadata, ZeroizingGuard,
};

use super::error::CipherBoxError;
use super::master_key::open;

#[derive(MemZer)]
#[memzer(drop)]
pub struct CipherBox<T>
where
    T: Default + FastZeroizable + ZeroizeMetadata + Encode + Decode + BytesRequired,
{
    initialized: bool,
    bytes_required: usize,
    codec_buffer: CodecBuffer,
    salt: [u8; 16],
    info: [u8; 23],
    nonce: Vec<u8>,
    ciphertext_with_tag: Vec<u8>,
    __drop_sentinel: DropSentinel,
    #[memzer(skip)]
    aead: Aead,
    #[memzer(skip)]
    entropy: SystemEntropySource,
    #[memzer(skip)]
    _marker: PhantomData<T>,
}

impl<T> CipherBox<T>
where
    T: Default
        + FastZeroizable
        + ZeroizeMetadata
        + ZeroizationProbe
        + Encode
        + Decode
        + BytesRequired,
{
    pub fn new() -> Self {
        Self {
            initialized: false,
            bytes_required: 0,
            codec_buffer: CodecBuffer::new(0),
            salt: [0u8; 16],
            nonce: vec![],
            ciphertext_with_tag: vec![],
            info: *b"redoubt-cipherbox:0.0.1",
            __drop_sentinel: DropSentinel::default(),
            aead: Aead::new(),
            entropy: SystemEntropySource::default(),
            _marker: PhantomData,
        }
    }

    fn derive_key(&self) -> Result<ZeroizingGuard<Vec<u8>>, CipherBoxError> {
        let mut out = Vec::<u8>::new();
        out.resize_with(self.aead.key_size(), || 0u8);

        open(&mut |ikm| {
            hkdf(ikm, &self.salt, &self.info, &mut out)
                .map_err(|e| BufferError::callback_error(e))?;
            Ok(())
        })?;

        Ok(ZeroizingGuard::new(out))
    }

    fn maybe_initialize(&mut self) -> Result<(), CipherBoxError> {
        if self.initialized {
            return Ok(());
        }

        self.entropy.fill_bytes(&mut self.salt)?;

        let mut value = T::default();

        self.encrypt(&mut value)?;
        self.initialized = true;

        Ok(())
    }

    fn encrypt(&mut self, value: &mut T) -> Result<(), CipherBoxError> {
        let mut derived_key = self.derive_key()?;

        self.nonce = self.aead.generate_nonce()?;
        self.ciphertext_with_tag =
            encrypt_encodable(&mut self.aead, &mut derived_key, &mut self.nonce, value)?;

        // wipe asap
        derived_key.fast_zeroize();

        Ok(())
    }

    fn decrypt(&mut self) -> Result<ZeroizingGuard<T>, CipherBoxError> {
        let mut derived_key = self.derive_key()?;
        let value = decrypt_decodable::<T>(
            &mut self.aead,
            &mut derived_key,
            &mut self.nonce,
            &mut self.ciphertext_with_tag,
        )?;

        Ok(value)
    }

    fn open_mut_dyn(
        &mut self,
        f: &mut dyn Fn(&mut ZeroizingGuard<T>),
    ) -> Result<(), CipherBoxError> {
        self.maybe_initialize()?;

        let mut value = self.decrypt()?;
        f(&mut value);
        self.encrypt(&mut value)?;

        // wipe asap
        value.fast_zeroize();
        debug_assert!(value.is_zeroized());

        Ok(())
    }

    fn open_dyn(&mut self, f: &mut dyn Fn(&ZeroizingGuard<T>)) -> Result<(), CipherBoxError> {
        self.maybe_initialize()?;

        let mut value = self.decrypt()?;
        f(&value);

        // wipe asap
        value.fast_zeroize();
        debug_assert!(value.is_zeroized());

        Ok(())
    }

    pub fn open<F>(&mut self, mut f: F) -> Result<(), CipherBoxError>
    where
        F: Fn(&ZeroizingGuard<T>),
    {
        self.open_dyn(&mut f)
    }

    pub fn open_mut<F>(&mut self, mut f: F) -> Result<(), CipherBoxError>
    where
        F: Fn(&mut ZeroizingGuard<T>),
    {
        self.open_mut_dyn(&mut f)
    }
}
