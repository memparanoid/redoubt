// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::AeadApi;
use memcodec::CodecBuffer;
use memzer::{FastZeroizable, ZeroizationProbe};

use crate::error::CipherBoxError;
use crate::traits::{Decryptable, Encryptable};

use super::consts::AAD;

#[cfg(test)]
pub(crate) fn to_encryptable_mut_dyn(x: &mut dyn Encryptable) -> &mut dyn Encryptable {
    x
}

#[cfg(test)]
pub(crate) fn to_decryptable_mut_dyn(x: &mut dyn Decryptable) -> &mut dyn Decryptable {
    x
}

#[inline(always)]
pub fn get_sizes<const N: usize>(
    fields: &[&mut dyn Encryptable; N],
) -> Result<[usize; N], CipherBoxError> {
    let mut sizes = [0usize; N];

    for (i, f) in fields.iter().enumerate() {
        sizes[i] = f.mem_bytes_required()?;
    }

    Ok(sizes)
}

#[inline(always)]
pub fn encrypt_into<const N: usize>(
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    fields: [&mut dyn Encryptable; N],
) -> Result<[Vec<u8>; N], CipherBoxError> {
    let sizes = get_sizes(&fields)?;
    let mut buffers: [CodecBuffer; N] = sizes.map(|s| CodecBuffer::new(s));

    encrypt_into_buffers(aead, aead_key, nonces, tags, fields, &mut buffers)
}

#[inline(always)]
fn try_encrypt_into_buffers<const N: usize>(
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    mut fields: [&mut dyn Encryptable; N],
    buffers: &mut [CodecBuffer; N],
) -> Result<[Vec<u8>; N], CipherBoxError> {
    for (idx, field) in fields.iter_mut().enumerate() {
        let buf = &mut buffers[idx];

        field.encode_into(buf)?;
        debug_assert!(
            !buf.is_zeroized(),
            "buffer[{}] should contain data after successful encode",
            idx
        );
    }

    let mut ciphertexts: [Vec<u8>; N] = core::array::from_fn(|i| buffers[i].export_as_vec());

    for (idx, plaintext) in ciphertexts.iter_mut().enumerate() {
        nonces[idx] = aead.api_generate_nonce()?;
        aead.api_encrypt(aead_key, &nonces[idx], &AAD, plaintext, &mut tags[idx])?;
    }

    Ok(ciphertexts)
}

#[inline(always)]
pub(crate) fn encrypt_into_buffers<const N: usize>(
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    fields: [&mut dyn Encryptable; N],
    buffers: &mut [CodecBuffer; N],
) -> Result<[Vec<u8>; N], CipherBoxError> {
    let result = try_encrypt_into_buffers(aead, aead_key, nonces, tags, fields, buffers);

    if result.is_err() {
        buffers.fast_zeroize();
        return Err(CipherBoxError::Poisoned);
    }

    result
}

#[inline(always)]
fn try_decrypt_from<const N: usize>(
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    ciphertexts: &mut [Vec<u8>; N],
    fields: &mut [&mut dyn Decryptable; N],
) -> Result<(), CipherBoxError> {
    for (idx, field) in fields.iter_mut().enumerate() {
        let nonce = &nonces[idx];
        let tag = &tags[idx];
        let ciphertext = &mut ciphertexts[idx];

        aead.api_decrypt(aead_key, nonce, &AAD, ciphertext, tag)?;
        field.decode_from(&mut ciphertext.as_mut_slice())?;
    }

    Ok(())
}

pub fn decrypt_from<const N: usize>(
    aead: &mut dyn AeadApi,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    ciphertexts: &mut [Vec<u8>; N],
    fields: &mut [&mut dyn Decryptable; N],
) -> Result<(), CipherBoxError> {
    let result = try_decrypt_from(aead, aead_key, nonces, tags, ciphertexts, fields);

    if result.is_err() {
        ciphertexts.fast_zeroize();
        return Err(CipherBoxError::Poisoned);
    }

    result
}
