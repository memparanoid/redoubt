// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use wasm_bindgen::prelude::*;

use memcodec::Codec;
use memvault::cipherbox;
use memzer::MemZer;

#[cipherbox(SecretBox)]
#[derive(Default, MemZer, Codec)]
#[memzer(drop)]
struct Secrets {
    master_key: [u8; 32],
    encryption_key: [u8; 32],
}

#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    format!("Hello from Redoubt WASM, {}!", name)
}

#[wasm_bindgen]
pub fn test_cipherbox() -> String {
    let mut secret_box = SecretBox::new();

    // Write secrets
    if let Err(e) = secret_box.open_mut(|secrets| {
        secrets.master_key.copy_from_slice(&[1u8; 32]);
        secrets.encryption_key.copy_from_slice(&[2u8; 32]);
    }) {
        return format!("Error writing: {:?}", e);
    }

    // Read back and verify
    match secret_box.open(|secrets| {
        assert_eq!(secrets.master_key[0], 1);
        assert_eq!(secrets.master_key[31], 1);
        assert_eq!(secrets.encryption_key[0], 2);
        assert_eq!(secrets.encryption_key[31], 2);
    }) {
        Ok(_) => "CipherBox works in WASM! ✅ Encryption/decryption verified".to_string(),
        Err(e) => format!("Error reading: {:?}", e),
    }
}
