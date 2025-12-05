// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
use memaead::Aead;
use memcodec::support::test_utils::{TestBreaker, TestBreakerBehaviour};

use crate::decrypt::decrypt_decodable;
use crate::encrypt::encrypt_encodable;

use super::utils::{create_aead_key, create_nonce};

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    let test_breaker_snapshot = format!("{:?}", test_breaker);

    let mut ciphertext = {
        let mut aead = Aead::new();
        let mut aead_key = create_aead_key(&aead, 1);
        let mut nonce = create_nonce(&aead, 2);
        encrypt_encodable(&mut aead, &mut aead_key, &mut nonce, &mut test_breaker)
            .expect("Failed to encrypt_mem_encodable(..)")
    };

    let recovered_test_breaker =
        decrypt_decodable::<TestBreaker>(&mut aead, &mut aead_key, &mut nonce, &mut ciphertext)
            .expect("Failed to decrypt_mem_decodable(..)");

    let recovered_test_breaker_snapshot = format!("{:?}", &*recovered_test_breaker);

    assert_eq!(test_breaker_snapshot, recovered_test_breaker_snapshot);
}
