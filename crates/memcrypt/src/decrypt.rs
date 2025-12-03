// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, aead::Buffer};
use zeroize::{Zeroize, Zeroizing};

use memcode::MemDecodable;
use memzer::{FastZeroizable, ZeroizationProbe};

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
///
/// # Example
///
/// ```
/// use memcrypt::{AeadKey, XNonce, encrypt_mem_encodable, decrypt_mem_decodable};
///
/// let mut key = AeadKey::default();
/// let mut key_material = [197u8; 32];
/// key.fill_exact(&mut key_material);
///
/// // key_material is guaranteed to be zeroized
/// assert!(key_material.iter().all(|&b| b == 0));
///
/// let mut nonce = XNonce::default();
/// let mut nonce_material = [193u8; 24];
/// nonce.fill_exact(&mut nonce_material);
///
/// // nonce_material is guaranteed to be zeroized
/// assert!(nonce_material.iter().all(|&b| b == 0));
///
/// // Encrypt sensitive data
/// let mut sensitive_data = vec![6317u64; 20];
/// let mut ciphertext = encrypt_mem_encodable(&mut key, &mut nonce, &mut sensitive_data)?;
///
/// // sensitive_data is guaranteed to be zeroized
/// assert!(sensitive_data.iter().all(|&v| v == 0));
///
/// // Decrypt with same key and nonce
/// let mut key2 = AeadKey::default();
/// let mut key2_material = [197u8; 32];
/// key2.fill_exact(&mut key2_material);
///
/// // key2_material is guaranteed to be zeroized
/// assert!(key2_material.iter().all(|&b| b == 0));
///
/// let mut nonce2 = XNonce::default();
/// let mut nonce2_material = [193u8; 24];
/// nonce2.fill_exact(&mut nonce2_material);
///
/// // nonce2_material is guaranteed to be zeroized
/// assert!(nonce2_material.iter().all(|&b| b == 0));
///
/// let recovered = decrypt_mem_decodable::<Vec<u64>>(&mut key2, &mut nonce2, &mut ciphertext)?;
///
/// // Recovered data matches original
/// assert_eq!(recovered.len(), 20);
/// assert!(recovered.iter().all(|&v| v == 6317));
/// # Ok::<(), memcrypt::CryptoError>(())
/// ```
pub fn decrypt_mem_decodable<T>(
    aead_key: &mut AeadKey,
    xnonce: &mut XNonce,
    ciphertext: &mut Vec<u8>,
) -> Result<Zeroizing<T>, CryptoError>
where
    T: MemDecodable + Default + Zeroize + FastZeroizable + ZeroizationProbe,
{
    let mut x = DecryptionMemZer::new(aead_key, xnonce, ciphertext);
    decrypt_mem_decodable_with::<T, _>(&mut x, |_, _| {})
}

pub fn decrypt_mem_decodable_with<T, F>(
    x: &mut DecryptionMemZer,
    #[allow(unused)] f: F,
) -> Result<Zeroizing<T>, CryptoError>
where
    T: MemDecodable + Default + Zeroize + FastZeroizable + ZeroizationProbe,
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

        // wipe unused
        x.aead_key.zeroize();

        cipher
    };

    // Stage: AeadBufferFillWithCiphertext
    {
        #[cfg(test)]
        f(DecryptStage::AeadBufferFillWithCiphertext, x);

        // Prepare AEAD buffer
        x.aead_buffer
            .zeroized_reserve_exact(x.ciphertext.len())
            .map_err(|_| {
                x.zeroize();
                CryptoError::AeadBufferNotZeroized
            })?;
        x.aead_buffer
            .extend_from_slice(&x.ciphertext)
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

        // wipe unused
        x.aead_buffer.zeroize();
    }

    Ok(Zeroizing::new(value))
}
