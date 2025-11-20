// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, aead::Buffer};
use zeroize::Zeroize;

use memcode::MemDecodable;
use memzer::{Secret, Zeroizable, ZeroizationProbe};

use crate::AeadKey;
use crate::XNonce;
use crate::consts::AAD;
use crate::error::CryptoError;
use crate::guards::DecryptionMemZer;

#[derive(PartialEq, Eq, Debug)]
#[allow(unused)]
pub enum DecryptStage {
    NewFromSlice,
    AeadBufferFillWithCiphertext,
    Decrypt,
    DrainFrom,
}

/// Decrypts a MemDecodable value using an in-place, allocation-free pipeline.
///
/// # Safety & Guarantees
/// - **No re-allocations:** Internal buffers are pre-reserved to match ciphertext length.
/// - **Memory hygiene:** On success, the ciphertext, AEAD key, and nonce are all zeroized.
///   On failure, *every intermediate buffer and field is zeroized*.
/// - **Ephemeral isolation:** The decrypted plaintext and AEAD material never coexist
///   in memory after the decryption stage completes.
///
/// # Stages
/// 1. [`NewFromSlice`] – creates the cipher instance from a key slice.
/// 2. [`AeadBufferFillWithCiphertext`] – fills AEAD buffer with ciphertext.
/// 3. [`Decrypt`] – decrypts the ciphertext into the AEAD buffer using `XChaCha20Poly1305`.
/// 4. [`DrainFrom`] – reconstructs `T` by draining data from the decrypted bytes.
///
/// # Returns
/// A [`Secret<T>`] holding the fully reconstructed value `T`.
/// The guard ensures automatic zeroization of `T` upon drop.
///
/// # Errors
/// - [`CryptoError::InvalidKeyLength`] if the key size is invalid.
/// - [`CryptoError::AeadBufferNotZeroized`] if the AEAD buffer is not fully zeroized before reserving.
/// - [`CryptoError::Decrypt`] if AEAD decryption fails.
/// - [`CryptoError::MemDecode`] if `MemDecodable` fails to reconstruct `T`.
pub fn decrypt_mem_decodable<T>(
    aead_key: &mut AeadKey,
    xnonce: &mut XNonce,
    ciphertext: &mut Secret<Vec<u8>>,
) -> Result<Secret<T>, CryptoError>
where
    T: MemDecodable + Default + Zeroize + Zeroizable + ZeroizationProbe,
{
    let mut x = DecryptionMemZer::new(aead_key, xnonce, ciphertext);
    decrypt_mem_decodable_with::<T, _>(&mut x, |_, _| {})
}

pub fn decrypt_mem_decodable_with<T, F>(
    x: &mut DecryptionMemZer,
    #[allow(unused)] f: F,
) -> Result<Secret<T>, CryptoError>
where
    T: MemDecodable + Default + Zeroize + Zeroizable + ZeroizationProbe,
    F: Fn(DecryptStage, &mut DecryptionMemZer),
{
    // State: NewFromSlice
    let cipher = {
        #[cfg(test)]
        f(DecryptStage::NewFromSlice, x);

        let key_slice = &x.aead_key.as_ref().as_slice()[0..x.aead_key_size];

        // wipe unused
        x.aead_key_size.zeroize();

        // SAFETY NOTE: `XChaCha20Poly1305::new_from_slice` creates the cipher from a slice.
        // The `chacha20poly1305` crate is compiled with feature `zeroize`, which ensures
        // the cipher's internal state is zeroized on Drop. We also zeroize our local key buffer.
        let cipher = XChaCha20Poly1305::new_from_slice(key_slice).map_err(|_| {
            x.zeroize();
            CryptoError::InvalidKeyLength
        })?;

        // Wipe unused
        x.aead_key.zeroize();

        cipher
    };

    // Stage: AeadBufferFillWithCiphertext
    {
        #[cfg(test)]
        f(DecryptStage::AeadBufferFillWithCiphertext, x);

        // Prepare AEAD buffer
        x.aead_buffer
            .zeroized_reserve_exact(x.ciphertext.expose().len())
            .map_err(|_| {
                x.zeroize();
                CryptoError::AeadBufferNotZeroized
            })?;
        x.aead_buffer
            .extend_from_slice(x.ciphertext.expose().as_ref())
            .expect("Infallible: AeadBuffer has been reserved with enough length");

        // wipe unused
        x.ciphertext.zeroize();
    }

    // Stage: Decrypt
    {
        #[cfg(test)]
        f(DecryptStage::Decrypt, x);

        cipher
            .decrypt_in_place(x.xnonce.as_ref(), AAD, &mut x.aead_buffer)
            .map_err(|_| {
                x.zeroize();
                CryptoError::Decrypt
            })?;

        // wipe unused
        x.xnonce.zeroize();
    }

    // Stage: DrainFrom
    let mut value = T::default();

    {
        #[cfg(test)]
        f(DecryptStage::DrainFrom, x);

        value.drain_from(x.aead_buffer.as_mut()).map_err(|e| {
            x.zeroize();
            CryptoError::MemDecode(e)
        })?;

        // Wipe unused
        x.aead_buffer.zeroize();
    }

    Ok(Secret::from(value))
}
