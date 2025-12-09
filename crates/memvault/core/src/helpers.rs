// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::Aead;
use memcodec::CodecBuffer;

use crate::error::CipherBoxError;
use crate::traits::{Decryptable, Encryptable};

use super::consts::AAD;

pub fn encrypt_into<const N: usize>(
    aead: &mut Aead,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    mut fields: [&mut dyn Encryptable; N],
) -> Result<[Vec<u8>; N], CipherBoxError> {
    let sizes: [usize; N] = {
        let mut sizes = [0usize; N];
        for (i, f) in fields.iter().enumerate() {
            sizes[i] = f.mem_bytes_required()?;
        }
        sizes
    };
    let mut buffers = sizes.map(|s| CodecBuffer::new(s));

    for (idx, field) in fields.iter_mut().enumerate() {
        let buf = &mut buffers[idx];
        field.encode_into(buf)?;
    }

    let mut ciphertexts: [Vec<u8>; N] = buffers.map(|b| b.to_vec());

    for (idx, plaintext) in ciphertexts.iter_mut().enumerate() {
        nonces[idx] = aead.generate_nonce()?;
        aead.encrypt(aead_key, &mut nonces[idx], &AAD, plaintext, &mut tags[idx])?;
    }

    Ok(ciphertexts)
}

pub fn decrypt_from<const N: usize>(
    aead: &mut Aead,
    aead_key: &[u8],
    nonces: &mut [Vec<u8>; N],
    tags: &mut [Vec<u8>; N],
    ciphertexts: &mut [Vec<u8>; N],
    mut fields: [&mut dyn Decryptable; N],
) -> Result<(), CipherBoxError> {
    for (idx, field) in fields.iter_mut().enumerate() {
        let nonce = &nonces[idx];
        let tag = &tags[idx];
        let ciphertext = &mut ciphertexts[idx];

        aead.decrypt(aead_key, nonce, &AAD, ciphertext, tag)?;
        field.decode_from(&mut ciphertext.as_mut_slice())?;
    }

    Ok(())
}
