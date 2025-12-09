// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::marker::PhantomData;

use memaead::Aead;
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
    ciphertexts: [Vec<u8>; N],
    nonces: [Vec<u8>; N],
    tags: [Vec<u8>; N],
    __drop_sentinel: DropSentinel,
    #[memzer(skip)]
    aead: Aead,
    #[memzer(skip)]
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
    pub fn new() -> Self {
        let aead = Aead::new();
        let nonce_size = aead.nonce_size();
        let tag_size = aead.tag_size();

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

    #[cold]
    #[inline(never)]
    fn maybe_initialize(&mut self) -> Result<(), CipherBoxError> {
        if self.initialized {
            return Ok(());
        }

        let master_key = leak_master_key(self.aead.key_size())?;
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

        self.aead.decrypt(
            aead_key,
            &self.nonces[M],
            &AAD,
            &mut self.ciphertexts[M],
            &self.tags[M],
        )?;

        field.decode_from(&mut self.ciphertexts[M].as_mut_slice())?;

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
        self.nonces[M] = self.aead.generate_nonce()?;

        self.aead.encrypt(
            aead_key,
            &mut self.nonces[M],
            &AAD,
            &mut self.ciphertexts[M],
            &mut self.tags[M],
        )?;

        Ok(())
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

    #[inline(always)]
    fn open_mut_dyn(&mut self, f: &mut dyn Fn(&mut T)) -> Result<(), CipherBoxError> {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.key_size())?;

        let mut value = self.decrypt_struct(&master_key)?;
        f(&mut value);
        self.encrypt_struct(&master_key, &mut value)?;

        Ok(())
    }

    #[inline(always)]
    fn open_dyn(&mut self, f: &mut dyn Fn(&T)) -> Result<(), CipherBoxError> {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.key_size())?;

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
        Field: Default + FastZeroizable + Encryptable + Decryptable + ZeroizationProbe,
        F: FnOnce(&Field),
    {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.key_size())?;

        let mut field = self.decrypt_field::<Field, M>(&master_key)?;
        f(&field);
        self.encrypt_field::<Field, M>(&master_key, &mut field)?;

        Ok(())
    }

    #[inline(always)]
    pub fn open_field_mut<Field, const M: usize, F>(&mut self, f: F) -> Result<(), CipherBoxError>
    where
        Field: Default + FastZeroizable + Encryptable + Decryptable + ZeroizationProbe,
        F: FnOnce(&mut Field),
    {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.key_size())?;

        let mut field = self.decrypt_field::<Field, M>(&master_key)?;
        f(&mut field);
        self.encrypt_field::<Field, M>(&master_key, &mut field)?;

        Ok(())
    }
}

// #[cfg(test)]
// mod perf_debug {
//     use core::marker::PhantomData;

//     use memaead::Aead;
//     use memalloc::AllockedVec;
//     use membuffer::BufferError;
//     use memcodec::{BytesRequired, Codec, CodecBuffer, Decode, Encode};
//     use memzer::{
//         DropSentinel, FastZeroizable, MemZer, ZeroizationProbe, ZeroizeMetadata, ZeroizingGuard,
//     };

//     use crate::decrypt_decodable::decrypt_decodable;
//     use crate::encrypt_encodable::encrypt_encodable;
//     use crate::error::CipherBoxError;
//     use crate::master_key::leak_master_key;

//     use super::CipherBox;

//     use std::time::Instant;

//     #[derive(MemZer, Codec)]
//     #[memzer(drop)]
//     pub struct WalletSecrets {
//         master_seed: [u8; 32],
//         encryption_key: [u8; 32],
//         signing_key: [u8; 64],
//         pin_hash: [u8; 32],
//         #[codec(default)]
//         __drop_sentinel: DropSentinel,
//     }

//     impl Default for WalletSecrets {
//         fn default() -> Self {
//             Self {
//                 master_seed: [0u8; 32],
//                 encryption_key: [0u8; 32],
//                 signing_key: [0u8; 64],
//                 pin_hash: [0u8; 32],
//                 __drop_sentinel: DropSentinel::default(),
//             }
//         }
//     }

//     #[test]
//     fn isolate_overhead() {
//         let mut cb = CipherBox::<WalletSecrets>::new();
//         let iterations = 10_000;

//         // 1. Solo leak_master_key
//         let start = Instant::now();
//         for _ in 0..iterations {
//             let key = leak_master_key(16).unwrap();
//             std::hint::black_box(&key);
//         }
//         println!(
//             "leak_master_key: {} ns",
//             start.elapsed().as_nanos() / iterations
//         );

//         let start = Instant::now();
//         let key = leak_master_key(16).unwrap();
//         for _ in 0..iterations {
//             let mut v = cb.decrypt(&key).unwrap();
//             cb.encrypt(&key, &mut v).unwrap();
//         }
//         println!(
//             "aead raw roundtrip: {} ns",
//             start.elapsed().as_nanos() / iterations
//         );

//         // 2. Solo decrypt (con key ya leakeada)
//         // let key = leak_master_key(16).unwrap();
//         // let start = Instant::now();
//         // for _ in 0..iterations {
//         //     let val = cb.decrypt(&key).unwrap();
//         //     std::hint::black_box(&val);
//         // }
//         // println!("decrypt: {} ns", start.elapsed().as_nanos() / iterations);

//         // // 3. Solo encrypt
//         // let start = Instant::now();
//         // for _ in 0..iterations {
//         //     let mut val = ZeroizingGuard::new(WalletSecrets::default());
//         //     cb.encrypt(&key, &mut val).unwrap();
//         // }
//         // println!("encrypt: {} ns", start.elapsed().as_nanos() / iterations);

//         // 4. El open_mut completo
//         let start = Instant::now();
//         for _ in 0..iterations {
//             cb.open_mut(|_| {}).unwrap();
//         }
//         println!("open_mut: {} ns", start.elapsed().as_nanos() / iterations);
//     }
// }
