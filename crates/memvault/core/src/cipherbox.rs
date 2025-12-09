// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::marker::PhantomData;

use memaead::Aead;
use memalloc::AllockedVec;
use membuffer::BufferError;
use memcodec::{BytesRequired, CodecBuffer, Decode, Encode};
use memzer::{
    DropSentinel, FastZeroizable, MemZer, ZeroizationProbe, ZeroizeMetadata, ZeroizingGuard,
};

use super::decrypt_decodable::decrypt_decodable;
use super::encrypt_encodable::encrypt_encodable;
use super::error::CipherBoxError;
use super::master_key::leak_master_key;

#[derive(MemZer)]
#[memzer(drop)]
pub struct CipherBox<T>
where
    T: Default + FastZeroizable + ZeroizeMetadata + Encode + Decode + BytesRequired,
{
    initialized: bool,
    bytes_required: usize,
    codec_buffer: CodecBuffer,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: AllockedVec<u8>,
    #[memzer(skip)]
    aead: Aead,
    #[memzer(skip)]
    _marker: PhantomData<T>,
    __drop_sentinel: DropSentinel,
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
        let aead = Aead::new();
        let tag = AllockedVec::with_capacity(aead.tag_size());

        Self {
            aead,
            tag,
            initialized: false,
            bytes_required: 0,
            codec_buffer: CodecBuffer::new(0),
            nonce: vec![],
            ciphertext: vec![],
            _marker: PhantomData,
            __drop_sentinel: DropSentinel::default(),
        }
    }

    #[inline(always)]
    pub fn encrypt(&mut self, aead_key: &[u8], value: &mut T) -> Result<(), CipherBoxError> {
        self.tag.fast_zeroize();
        self.nonce = self.aead.generate_nonce()?;
        self.ciphertext = encrypt_encodable(
            &mut self.aead,
            aead_key,
            self.nonce.as_slice(),
            self.tag.as_capacity_mut_slice(),
            value,
        )?;
        Ok(())
    }

    #[cold]
    #[inline(never)]
    fn maybe_initialize(&mut self) -> Result<(), CipherBoxError> {
        if self.initialized {
            return Ok(());
        }

        let master_key = leak_master_key(self.aead.key_size())?;
        let mut value = ZeroizingGuard::new(T::default());

        self.encrypt(&master_key, &mut value)?;
        self.initialized = true;

        Ok(())
    }

    #[inline(always)]
    pub fn decrypt(&mut self, aead_key: &[u8]) -> Result<ZeroizingGuard<T>, CipherBoxError> {
        let value = decrypt_decodable::<T>(
            &mut self.aead,
            aead_key,
            self.nonce.as_slice(),
            self.tag.as_capacity_slice(),
            &mut self.ciphertext,
        )?;

        Ok(value)
    }

    #[inline(always)]
    fn open_mut_dyn(&mut self, f: &mut dyn Fn(&mut T)) -> Result<(), CipherBoxError> {
        Ok(())
    }

    #[inline(always)]
    fn open_dyn(&mut self, f: &mut dyn Fn(&T)) -> Result<(), CipherBoxError> {
        Ok(())
    }

    #[inline(always)]
    pub fn open<F>(&mut self, mut f: F) -> Result<(), CipherBoxError>
    where
        F: Fn(&T),
    {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.key_size())?;

        let mut value = self.decrypt(&master_key)?;
        f(&mut value);
        self.encrypt(&master_key, &mut value)?;

        Ok(())
    }

    #[inline(always)]
    pub fn open_mut<F>(&mut self, mut f: F) -> Result<(), CipherBoxError>
    where
        F: Fn(&mut T),
    {
        self.maybe_initialize()?;

        let master_key = leak_master_key(self.aead.key_size())?;

        let mut value = self.decrypt(&master_key)?;
        f(&mut value);
        self.encrypt(&master_key, &mut value)?;

        Ok(())
    }
}

#[cfg(test)]
mod perf_debug {
    use core::marker::PhantomData;

    use memaead::Aead;
    use memalloc::AllockedVec;
    use membuffer::BufferError;
    use memcodec::{BytesRequired, Codec, CodecBuffer, Decode, Encode};
    use memzer::{
        DropSentinel, FastZeroizable, MemZer, ZeroizationProbe, ZeroizeMetadata, ZeroizingGuard,
    };

    use crate::decrypt_decodable::decrypt_decodable;
    use crate::encrypt_encodable::encrypt_encodable;
    use crate::error::CipherBoxError;
    use crate::master_key::leak_master_key;

    use super::CipherBox;

    use std::time::Instant;

    #[derive(MemZer, Codec)]
    #[memzer(drop)]
    pub struct WalletSecrets {
        master_seed: [u8; 32],
        encryption_key: [u8; 32],
        signing_key: [u8; 64],
        pin_hash: [u8; 32],
        #[codec(default)]
        __drop_sentinel: DropSentinel,
    }

    impl Default for WalletSecrets {
        fn default() -> Self {
            Self {
                master_seed: [0u8; 32],
                encryption_key: [0u8; 32],
                signing_key: [0u8; 64],
                pin_hash: [0u8; 32],
                __drop_sentinel: DropSentinel::default(),
            }
        }
    }

    #[test]
    fn isolate_overhead() {
        let mut cb = CipherBox::<WalletSecrets>::new();
        let iterations = 10_000;

        // 1. Solo leak_master_key
        let start = Instant::now();
        for _ in 0..iterations {
            let key = leak_master_key(16).unwrap();
            std::hint::black_box(&key);
        }
        println!(
            "leak_master_key: {} ns",
            start.elapsed().as_nanos() / iterations
        );

        let start = Instant::now();
        let key = leak_master_key(16).unwrap();
        for _ in 0..iterations {
            let mut v = cb.decrypt(&key).unwrap();
            cb.encrypt(&key, &mut v).unwrap();
        }
        println!(
            "aead raw roundtrip: {} ns",
            start.elapsed().as_nanos() / iterations
        );

        // 2. Solo decrypt (con key ya leakeada)
        // let key = leak_master_key(16).unwrap();
        // let start = Instant::now();
        // for _ in 0..iterations {
        //     let val = cb.decrypt(&key).unwrap();
        //     std::hint::black_box(&val);
        // }
        // println!("decrypt: {} ns", start.elapsed().as_nanos() / iterations);

        // // 3. Solo encrypt
        // let start = Instant::now();
        // for _ in 0..iterations {
        //     let mut val = ZeroizingGuard::new(WalletSecrets::default());
        //     cb.encrypt(&key, &mut val).unwrap();
        // }
        // println!("encrypt: {} ns", start.elapsed().as_nanos() / iterations);

        // 4. El open_mut completo
        let start = Instant::now();
        for _ in 0..iterations {
            cb.open_mut(|_| {}).unwrap();
        }
        println!("open_mut: {} ns", start.elapsed().as_nanos() / iterations);
    }
}
