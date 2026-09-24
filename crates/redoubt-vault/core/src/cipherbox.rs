// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec;

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

use redoubt_aead::{Aead, AeadError};
use redoubt_codec::{BytesRequired, Decode, Encode, RedoubtCodecBuffer};
use redoubt_zero::{
    FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeMetadata, ZeroizingGuard,
};

use super::consts::AAD;
use super::error::CipherBoxError;
use super::master_key::leak_master_key;
use super::traits::{DecryptStruct, Decryptable, EncryptStruct, Encryptable};
use super::types::{Ciphertexts, Data, DataBuffers, Nonces, Tags};

#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub struct CipherBox<T, const N: usize>
where
    T: Default
        + FastZeroizable
        + ZeroizeMetadata
        + EncryptStruct<N>
        + DecryptStruct<N>
        + Encode
        + Decode
        + BytesRequired,
{
    initialized: bool,
    /// Starts as `true`, becomes `false` after `fast_zeroize()` (since false = 0x00).
    /// Used to distinguish intentional zeroization from corruption.
    pristine: bool,
    /// Starts as `false`, becomes `true` when an operation fails.
    ///
    /// Atomic because a read takes the box by shared reference, and a read is
    /// one of the operations that can fail. `Relaxed` throughout: the flag
    /// only ever latches one way and publishes nothing behind it, so a reader
    /// that misses it by a moment refuses a moment later instead.
    poisoned: AtomicBool,
    key_size: usize,
    ciphertexts: Ciphertexts<N>,
    nonces: Nonces<N>,
    tags: Tags<N>,
    tmp_field_codec_buff: RedoubtCodecBuffer,
    /// Runtime verification that zeroization happened, for the tests that
    /// read it.
    ///
    /// Gated because it is an `Arc<AtomicBool>` — one heap allocation per
    /// value, in a type whose whole reason for existing is to leave nothing
    /// in memory. Nothing reads it outside this crate's own tests, and the
    /// `RedoubtZero` derive treats the field as optional.
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
    #[fast_zeroize(skip)]
    aead: Aead,
    #[fast_zeroize(skip)]
    _marker: PhantomData<T>,
}

impl<T, const N: usize> CipherBox<T, N>
where
    T: Default
        + FastZeroizable
        + ZeroizeMetadata
        + ZeroizationProbe
        + EncryptStruct<N>
        + DecryptStruct<N>
        + Encode
        + Decode
        + BytesRequired,
{
    #[cfg(test)]
    pub(crate) fn unzeroize(&mut self) {
        self.pristine = true;
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_change_api_key_size(&mut self, key_size: usize) {
        self.key_size = key_size;
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_tmp_codec_buff(&self) -> &RedoubtCodecBuffer {
        &self.tmp_field_codec_buff
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_ciphertexts(&self) -> &Ciphertexts<N> {
        &self.ciphertexts
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_field_ciphertext<const M: usize>(
        &self,
    ) -> &super::types::Ciphertext {
        &self.ciphertexts[M]
    }

    pub fn new(aead: Aead) -> Self {
        let key_size = aead.key_size();
        let nonce_size = aead.nonce_size();
        let tag_size = aead.tag_size();

        let nonces: Nonces<N> = core::array::from_fn(|_| {
            let nonce = vec![0; nonce_size];
            nonce
        });

        let tags: Tags<N> = core::array::from_fn(|_| {
            let tag = vec![0; tag_size];
            tag
        });

        let ciphertexts: Ciphertexts<N> = core::array::from_fn(|_| vec![]);

        Self {
            aead,
            key_size,
            tags,
            nonces,
            ciphertexts,
            initialized: false,
            pristine: true,
            poisoned: AtomicBool::new(false),
            tmp_field_codec_buff: RedoubtCodecBuffer::default(),
            #[cfg(test)]
            __sentinel: redoubt_zero::ZeroizeOnDropSentinel::default(),
            _marker: PhantomData,
        }
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn assert_healthy(&self) -> Result<(), CipherBoxError> {
        if !self.pristine {
            return Err(CipherBoxError::Zeroized);
        }

        if self.poisoned.load(Ordering::Relaxed) {
            return Err(CipherBoxError::Poisoned);
        }

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn encrypt_struct(
        &mut self,
        aead_key: &[u8],
        value: &mut T,
    ) -> Result<(), CipherBoxError> {
        let result = value.encrypt_into(&mut self.aead, aead_key, &mut self.nonces, &mut self.tags);

        match result {
            Ok(ciphertexts) => {
                self.ciphertexts = ciphertexts;
                // Sealing every field at once is what a box is initialized by,
                // so this is the only place that can say so.
                self.initialized = true;
                Ok(())
            }
            Err(_) => {
                self.poisoned.store(true, Ordering::Relaxed);
                Err(CipherBoxError::Poisoned)
            }
        }
    }

    #[inline(always)]
    pub(crate) fn decrypt_struct(
        &self,
        aead_key: &[u8],
    ) -> Result<ZeroizingGuard<T>, CipherBoxError> {
        // Decryption drains what it works on, so it works on a clone and the
        // sealed fields survive the read.
        let mut data: DataBuffers<N> = core::array::from_fn(|i| self.ciphertexts[i].clone());

        self.decrypt_struct_from(aead_key, &mut data)
    }

    #[inline(always)]
    pub(crate) fn decrypt_struct_from(
        &self,
        aead_key: &[u8],
        data: &mut DataBuffers<N>,
    ) -> Result<ZeroizingGuard<T>, CipherBoxError> {
        let mut value = ZeroizingGuard::<T>::from_default();
        let result = value.decrypt_from(&self.aead, aead_key, &self.nonces, &self.tags, data);

        match result {
            Ok(_) => Ok(value),
            Err(_) => {
                self.poisoned.store(true, Ordering::Relaxed);
                Err(CipherBoxError::Poisoned)
            }
        }
    }

    /// Seals every field with its default, where nothing has sealed the box
    /// yet.
    ///
    /// What needs this is a write that reaches one field: it seals that one
    /// and leaves the rest as they were, so on a box where the rest are empty
    /// it would return having sealed a single field, with the box still
    /// reading as unsealed and the write it just took lost at the next read.
    #[cold]
    #[inline(never)]
    pub(crate) fn maybe_initialize(&mut self) -> Result<(), CipherBoxError> {
        if self.initialized {
            return Ok(());
        }

        let master_key = leak_master_key(self.key_size).map_err(CipherBoxError::from)?;
        let mut value = ZeroizingGuard::<T>::from_default();

        self.encrypt_struct(&master_key, &mut value)
    }

    /// Decrypts field `M`, leaving `ciphertexts[M]` intact.
    ///
    /// Decryption drains the buffer it works on, so it works on a clone: the
    /// sealed field survives the read, and a caller can be handed the
    /// plaintext without the box having to seal it again. What is left in the
    /// clone is zeros, because `decode_from` wipes each range as it reads it.
    #[inline(always)]
    pub(crate) fn try_decrypt_field<F, const M: usize>(
        &self,
        aead_key: &[u8],
        field: &mut F,
        data: &mut Data,
    ) -> Result<(), CipherBoxError>
    where
        F: Default + Decryptable + ZeroizationProbe,
    {
        // Clone ciphertext so we don't drain the original
        *data = self.ciphertexts[M].clone();
        self.aead
            .decrypt(aead_key, &self.nonces[M], AAD, data, &self.tags[M])?;

        // `data` is guaranteed to be zeroized by `decode_from`
        field.decode_from(&mut data.as_mut_slice())?;

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn decrypt_field<F, const M: usize>(
        &self,
        aead_key: &[u8],
        field: &mut F,
    ) -> Result<(), CipherBoxError>
    where
        F: Default + Decryptable + ZeroizationProbe,
    {
        let mut data = Data::default();

        self.decrypt_field_into::<F, M>(aead_key, field, &mut data)
    }

    #[inline(always)]
    pub(crate) fn decrypt_field_into<F, const M: usize>(
        &self,
        aead_key: &[u8],
        field: &mut F,
        data: &mut Data,
    ) -> Result<(), CipherBoxError>
    where
        F: Default + Decryptable + ZeroizationProbe,
    {
        let result = self.try_decrypt_field::<F, M>(aead_key, field, data);

        if result.is_err() {
            data.fast_zeroize();
            self.poisoned.store(true, Ordering::Relaxed);
            return Err(CipherBoxError::Poisoned);
        }

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn try_encrypt_field<F, const M: usize>(
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
        self.nonces[M] = self.aead.generate_nonce().inspect_err(|_| {
            self.ciphertexts[M].fast_zeroize();
        })?;
        self.aead
            .encrypt(
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
            // No nonce came back, so nothing was sealed and nothing here was
            // written over. A box that is intact is not poisoned.
            Err(CipherBoxError::Aead(AeadError::NonceEntropy(err))) => {
                Err(CipherBoxError::Aead(AeadError::NonceEntropy(err)))
            }
            _ => {
                self.poisoned.store(true, Ordering::Relaxed);
                Err(CipherBoxError::Poisoned)
            }
        }
    }

    /// Provides read-only access to the entire struct via a callback.
    ///
    /// The sealed fields are not touched: the callback is handed a clone, and
    /// nothing is written back, so a read costs a decrypt and no encrypt.
    ///
    /// Reading one field goes through `leak_field` instead, which clones and
    /// decrypts that field alone.
    #[inline(always)]
    pub(crate) fn open_dyn<R, E>(
        &self,
        f: &mut dyn FnMut(&T) -> Result<R, E>,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy().map_err(E::from)?;

        let mut value = self.open_value().map_err(E::from)?;

        let mut result = f(&value).inspect_err(|_| {
            // wipe asap
            value.fast_zeroize();
        })?;

        Ok(ZeroizingGuard::from_mut(&mut result))
    }

    /// The struct a read sees, which is `T::default()` where nothing has
    /// sealed the box yet.
    ///
    /// An unsealed box holds no ciphertexts, so there is nothing to open and
    /// the master key is never asked for.
    #[inline(always)]
    pub(crate) fn open_value(&self) -> Result<ZeroizingGuard<T>, CipherBoxError> {
        if !self.initialized {
            return Ok(ZeroizingGuard::<T>::from_default());
        }

        let master_key = leak_master_key(self.key_size).map_err(CipherBoxError::from)?;

        self.decrypt_struct(&master_key)
    }

    /// Provides mutable access to the entire struct via a callback.
    ///
    /// A callback that returns `Err` leaves the sealed fields as they were:
    /// what it was handed is a clone, and only a callback that returns `Ok` is
    /// followed by the reseal that commits it.
    #[inline(always)]
    pub(crate) fn open_mut_dyn<R, E>(
        &mut self,
        f: &mut dyn FnMut(&mut T) -> Result<R, E>,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy().map_err(E::from)?;

        let master_key = leak_master_key(self.key_size).map_err(CipherBoxError::from)?;

        // An unsealed box has no ciphertexts to open, and the reseal below is
        // what first seals it.
        let mut value = if !self.initialized {
            ZeroizingGuard::<T>::from_default()
        } else {
            self.decrypt_struct(&master_key).map_err(E::from)?
        };

        let mut result = f(&mut value).inspect_err(|_| {
            // wipe asap
            value.fast_zeroize();
        })?;

        self.encrypt_struct(&master_key, &mut value)?;

        Ok(ZeroizingGuard::from_mut(&mut result))
    }

    #[inline(always)]
    pub(crate) fn open_field_dyn<Field, const M: usize, R, E>(
        &self,
        f: &mut dyn FnMut(&Field) -> Result<R, E>,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy()?;

        let mut field = self.open_field_value::<Field, M>()?;

        let mut result = f(&field).inspect_err(|_| {
            // wipe asap
            field.fast_zeroize();
        })?;

        Ok(ZeroizingGuard::from_mut(&mut result))
    }

    /// The field a read sees, which is `Field::default()` where nothing has
    /// sealed the box yet.
    ///
    /// An unsealed box holds no ciphertexts, so there is nothing to open and
    /// the master key is never asked for.
    #[inline(always)]
    pub(crate) fn open_field_value<Field, const M: usize>(
        &self,
    ) -> Result<ZeroizingGuard<Field>, CipherBoxError>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
    {
        let mut field = ZeroizingGuard::<Field>::from_default();

        if !self.initialized {
            return Ok(field);
        }

        let master_key = leak_master_key(self.key_size).map_err(CipherBoxError::from)?;

        self.decrypt_field::<Field, M>(&master_key, &mut field)?;

        Ok(field)
    }

    #[inline(always)]
    pub(crate) fn open_field_mut_dyn<Field, const M: usize, R, E>(
        &mut self,
        f: &mut dyn FnMut(&mut Field) -> Result<R, E>,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        Field: Default + FastZeroizable + Encryptable + Decryptable + ZeroizationProbe,
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy()?;
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.key_size).map_err(CipherBoxError::from)?;
        let mut field = ZeroizingGuard::<Field>::from_default();

        self.decrypt_field::<Field, M>(&master_key, &mut field)?;

        let mut result = f(&mut field).inspect_err(|_| {
            // wipe asap
            field.fast_zeroize();
        })?;

        self.encrypt_field::<Field, M>(&master_key, &mut field)?;

        Ok(ZeroizingGuard::from_mut(&mut result))
    }

    #[inline(always)]
    pub fn open<F, R, E>(&self, mut f: F) -> Result<ZeroizingGuard<R>, E>
    where
        F: FnMut(&T) -> Result<R, E>,
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.open_dyn(&mut f)
    }

    #[inline(always)]
    pub fn open_mut<F, R, E>(&mut self, mut f: F) -> Result<ZeroizingGuard<R>, E>
    where
        F: FnMut(&mut T) -> Result<R, E>,
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.open_mut_dyn(&mut f)
    }

    #[inline(always)]
    pub fn open_field<Field, const M: usize, F, R, E>(
        &self,
        mut f: F,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
        F: FnMut(&Field) -> Result<R, E>,
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.open_field_dyn::<Field, M, R, E>(&mut f)
    }

    #[inline(always)]
    pub fn open_field_mut<Field, const M: usize, F, R, E>(
        &mut self,
        mut f: F,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        Field: Default + FastZeroizable + Encryptable + Decryptable + ZeroizationProbe,
        F: FnMut(&mut Field) -> Result<R, E>,
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.open_field_mut_dyn::<Field, M, R, E>(&mut f)
    }

    /// Leaks a single field by returning ownership (no re-encryption needed).
    ///
    /// # Why "leak"?
    ///
    /// This returns ownership of the decrypted field, allowing it to outlive the callback.
    /// The field is wrapped in `ZeroizingGuard` for automatic cleanup when dropped.
    ///
    /// # Performance
    ///
    /// This is the MOST EFFICIENT way to read a single field because:
    /// 1. Only clones the field's ciphertext (not the entire struct)
    /// 2. No re-encryption required (original ciphertext remains intact)
    /// 3. Avoids the full struct decrypt-encrypt cycle of `open`
    ///
    /// # Design Note
    ///
    /// `decrypt_field` clones `ciphertexts[M]` before decryption, allowing this method
    /// to return ownership without losing the encrypted data. See `try_decrypt_field`
    /// for implementation details.
    ///
    /// # Usage Pattern
    ///
    /// Prefer this over `open_field` when you need to:
    /// - Perform operations outside the callback scope
    /// - Use the field data across multiple statements
    /// - Implement the leak-operate-commit pattern for fallible operations
    #[inline(always)]
    pub fn leak_field<Field, const M: usize, E>(&self) -> Result<ZeroizingGuard<Field>, E>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy()?;

        self.open_field_value::<Field, M>().map_err(E::from)
    }
}
