// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec;

use core::marker::PhantomData;

use redoubt_aead::AeadApi;
use redoubt_codec::{BytesRequired, Decode, Encode, RedoubtCodecBuffer};
use redoubt_zero::{
    FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeMetadata, ZeroizeOnDropSentinel,
    ZeroizingGuard,
};

use super::consts::AAD;
use super::error::CipherBoxError;
use super::master_key::leak_master_key;
use super::traits::{DecryptStruct, Decryptable, EncryptStruct, Encryptable};
use super::types::{Ciphertext, Ciphertexts, Nonces, Tags};

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
    /// Starts as `true`, becomes `false` after `fast_zeroize()` (since false = 0x00).
    /// Used to distinguish intentional zeroization from corruption.
    pristine: bool,
    /// Starts as `false`, becomes `true` when an operation fails.
    poisoned: bool,
    key_size: usize,
    ciphertexts: Ciphertexts<N>,
    tmp_ciphertexts: Ciphertexts<N>,
    nonces: Nonces<N>,
    tags: Tags<N>,
    tmp_field_cyphertext: Ciphertext,
    tmp_field_codec_buff: RedoubtCodecBuffer,
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
    pub(crate) fn __unsafe_get_tmp_ciphertext(&mut self) -> &Ciphertext {
        &self.tmp_field_cyphertext
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_tmp_codec_buff(&mut self) -> &RedoubtCodecBuffer {
        &self.tmp_field_codec_buff
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_tmp_ciphertexts(&self) -> &Ciphertexts<N> {
        &self.tmp_ciphertexts
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_get_field_ciphertext<const M: usize>(&mut self) -> &Ciphertext {
        &self.ciphertexts[M]
    }

    pub fn new(aead: A) -> Self {
        let key_size = aead.api_key_size();
        let nonce_size = aead.api_nonce_size();
        let tag_size = aead.api_tag_size();

        let nonces: Nonces<N> = core::array::from_fn(|_| {
            let nonce = vec![0; nonce_size];
            nonce
        });

        let tags: Tags<N> = core::array::from_fn(|_| {
            let tag = vec![0; tag_size];
            tag
        });

        let ciphertexts: Ciphertexts<N> = core::array::from_fn(|_| vec![]);
        let tmp_ciphertexts: Ciphertexts<N> = core::array::from_fn(|_| vec![]);

        Self {
            aead,
            key_size,
            tags,
            nonces,
            ciphertexts,
            tmp_ciphertexts,
            initialized: false,
            pristine: true,
            poisoned: false,
            tmp_field_cyphertext: Ciphertext::default(),
            tmp_field_codec_buff: RedoubtCodecBuffer::default(),
            __sentinel: ZeroizeOnDropSentinel::default(),
            _marker: PhantomData,
        }
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn assert_healthy(&self) -> Result<(), CipherBoxError> {
        if !self.pristine {
            return Err(CipherBoxError::Zeroized);
        }

        if self.poisoned {
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
                self.poisoned = true;
                Err(CipherBoxError::Poisoned)
            }
        }
    }

    #[inline(always)]
    pub fn decrypt_struct(&mut self, aead_key: &[u8]) -> Result<ZeroizingGuard<T>, CipherBoxError> {
        // Clone ciphertexts for rollback capability
        for i in 0..N {
            self.tmp_ciphertexts[i] = self.ciphertexts[i].clone();
        }

        let mut value = ZeroizingGuard::<T>::from_default();
        let result = value.decrypt_from(
            &mut self.aead,
            aead_key,
            &mut self.nonces,
            &mut self.tags,
            &mut self.tmp_ciphertexts,
        );

        match result {
            Ok(_) => Ok(value),
            Err(_) => {
                self.poisoned = true;
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
            self.poisoned = true;
            CipherBoxError::Poisoned
        })?;
        let mut value = ZeroizingGuard::<T>::from_default();

        self.encrypt_struct(&master_key, &mut value)?;
        self.initialized = true;

        Ok(())
    }

    /// Decrypts a single field by cloning the ciphertext first.
    ///
    /// # Design Note
    ///
    /// This method CLONES `ciphertexts[M]` into `tmp_field_cyphertext` before decryption.
    /// This is critical because:
    /// - Decryption is in-place and destructive (drains the buffer)
    /// - By operating on a copy, the original ciphertext remains intact
    /// - This enables `leak_field` to return ownership without re-encryption
    /// - The temporary buffer is zeroized by `decode_from` (line 202)
    ///
    /// # Memory Safety
    ///
    /// Zeroization of `tmp_field_cyphertext` is verified in:
    /// - Happy path: `test_decrypt_field_ok`
    /// - Error path: `test_decrypt_field_propagates_decode_error`
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
            self.poisoned = true;
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
                self.poisoned = true;
                Err(CipherBoxError::Poisoned)
            }
        }
    }

    /// Provides read-only access to the entire struct via a callback.
    ///
    /// # Design Note: Why decrypt → encrypt?
    ///
    /// This method performs a full decrypt-encrypt cycle even for read-only access.
    /// This seems wasteful but is necessary because:
    ///
    /// 1. `decrypt_struct` operates on `tmp_ciphertexts[]` (cloned from `ciphertexts[]`)
    /// 2. Without re-encryption, the ciphertexts would be permanently lost
    ///
    /// 3. The alternative (duplicating logic between `open` and `open_mut`) is worse:
    ///    - More code to maintain
    ///    - Higher risk of divergence
    ///    - `open` is rarely used in practice (most code uses `leak_field`)
    ///
    /// # Usage Note
    ///
    /// For better performance when reading a single field, prefer `leak_field` which
    /// avoids the full struct decrypt-encrypt cycle by cloning only the field's ciphertext.
    #[inline(always)]
    fn open_dyn<R, E>(
        &mut self,
        f: &mut dyn FnMut(&T) -> Result<R, E>,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy().map_err(E::from)?;
        self.maybe_initialize().map_err(E::from)?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.poisoned = true;
            E::from(CipherBoxError::Poisoned)
        })?;
        let mut value = self.decrypt_struct(&master_key).map_err(E::from)?;

        let mut result = f(&value).inspect_err(|_| {
            // wipe asap
            value.fast_zeroize();
        })?;

        self.encrypt_struct(&master_key, &mut value)?;

        Ok(ZeroizingGuard::from_mut(&mut result))
    }

    /// Provides mutable access to the entire struct via a callback.
    ///
    /// # Design Note
    ///
    /// This method performs decrypt → callback → encrypt:
    /// 1. `decrypt_struct` clones `ciphertexts[]` into `tmp_ciphertexts[]`
    /// 2. Decrypts `tmp_ciphertexts[]` into plaintext `value`
    /// 3. Callback modifies `value` and returns `Result<R, E>`
    /// 4. If callback succeeds: re-encrypts `value` and commits changes
    /// 5. If callback fails: discards changes, original `ciphertexts[]` remain intact
    ///
    /// # Rollback Capability
    ///
    /// Unlike the old design, callbacks CAN now return `Result`:
    /// - `decrypt_struct` operates on `tmp_ciphertexts[]` (cloned from `ciphertexts[]`)
    /// - If callback fails, original `ciphertexts[]` are preserved (rollback)
    /// - If callback succeeds, changes are committed via `encrypt_struct`
    ///
    /// # Error Handling
    ///
    /// The error type `E` must implement `From<CipherBoxError>` to handle both:
    /// - CipherBox internal errors (decrypt/encrypt failures)
    /// - User callback errors
    #[inline(always)]
    fn open_mut_dyn<R, E>(
        &mut self,
        f: &mut dyn FnMut(&mut T) -> Result<R, E>,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy().map_err(E::from)?;
        self.maybe_initialize().map_err(E::from)?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.poisoned = true;
            E::from(CipherBoxError::Poisoned)
        })?;
        let mut value = self.decrypt_struct(&master_key).map_err(E::from)?;

        let mut result = f(&mut value).inspect_err(|_| {
            // wipe asap
            value.fast_zeroize();
        })?;

        self.encrypt_struct(&master_key, &mut value)?;

        Ok(ZeroizingGuard::from_mut(&mut result))
    }

    #[inline(always)]
    pub fn open_field_dyn<Field, const M: usize, R, E>(
        &mut self,
        f: &mut dyn FnMut(&Field) -> Result<R, E>,
    ) -> Result<ZeroizingGuard<R>, E>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
        R: Default + FastZeroizable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy()?;
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.poisoned = true;
            CipherBoxError::Poisoned
        })?;
        let mut field = ZeroizingGuard::<Field>::from_default();

        self.decrypt_field::<Field, M>(&master_key, &mut field)?;

        let mut result = f(&field).inspect_err(|_| {
            // wipe asap
            field.fast_zeroize();
        })?;

        Ok(ZeroizingGuard::from_mut(&mut result))
    }

    #[inline(always)]
    pub fn open_field_mut_dyn<Field, const M: usize, R, E>(
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

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.poisoned = true;
            CipherBoxError::Poisoned
        })?;
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
    pub fn open<F, R, E>(&mut self, mut f: F) -> Result<ZeroizingGuard<R>, E>
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
        &mut self,
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
    pub fn leak_field<Field, const M: usize, E>(&mut self) -> Result<ZeroizingGuard<Field>, E>
    where
        Field: Default + FastZeroizable + Decryptable + ZeroizationProbe,
        E: From<CipherBoxError>,
    {
        self.assert_healthy()?;
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.key_size).map_err(|_| {
            self.poisoned = true;
            CipherBoxError::Poisoned
        })?;
        let mut field = ZeroizingGuard::<Field>::from_default();

        self.decrypt_field::<Field, M>(&master_key, &mut field)?;

        Ok(field)
    }
}
