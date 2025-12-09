// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::Aead;
use memcodec::Decode;
use memzer::{FastZeroizable, ZeroizationProbe, ZeroizingGuard};

use super::consts::AAD;
use super::error::CryptoError;

#[inline(always)]
pub fn decrypt_decodable<T>(
    aead: &mut Aead,
    aead_key: &[u8],
    nonce: &[u8],
    tag: &[u8],
    mut ciphertext: &mut [u8],
) -> Result<ZeroizingGuard<T>, CryptoError>
where
    T: Default + Decode + FastZeroizable + ZeroizationProbe,
{
    let mut value = ZeroizingGuard::new(T::default());

    aead.decrypt(&aead_key, &nonce, &AAD, ciphertext, tag)?;
    // ciphertext is now plaintext
    value.decode_from(&mut ciphertext)?;

    // CRITICAL:
    // wipe ASAP, ciphertext contains plaintext data after decrypt.
    ciphertext.fast_zeroize();

    Ok(value)
}
